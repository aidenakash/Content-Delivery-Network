 async signIn(domain_id: number, user_code: string, user_password: string | null = null, fcm_tokens: FcmToken, is_google_login: boolean = false, req:any, res:any): Promise<ApiResponse> {
    try {

      const device_type = fcm_tokens.type;

      // email regex
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      let condition: any = {};
      if (emailRegex.test(user_code)) {
        condition = { user_email: (user_code).trim() }
        domain_id && (condition['domain_id'] = domain_id)
      }
      else {
        condition = { user_code: (user_code).toUpperCase().trim() }
        domain_id && (condition['domain_id'] = domain_id)
      }
      if (device_type === 'mobile') {
        const usersWithSameCode = await this.userRepository.findAll({
          where: condition,
        });

        let matchCount = 0;

        if (usersWithSameCode.length > 0) {
          for (const user of usersWithSameCode) {
            if (compareSync(user_password, user.user_password)) {
              matchCount++;
            }
          }
        }

        if (matchCount > 1) {
          return await responseMessageGenerator(
            "failure",
            "Multiple users found with the same Employee Code and Password. Please use your Email ID instead for login.",
            {}
          );
        }
      }
      if (device_type != 'mobile') {
        if (!domain_id)
          throw new CustomUnauthorizedException(
            "Your account has not yet been activated",
            HttpStatus.BAD_REQUEST
          );
        const domainIsActive = await this.ClientDomainModel.findOne({ where: { id: domain_id, is_active: 1 } });
        if (!domainIsActive)
          throw new CustomUnauthorizedException(
            "Your account has not yet been activated",
            HttpStatus.BAD_REQUEST
          );
      }

      const user = await this.userRepository.findOne({
        where: condition,
        include: [{ association: 'employee_personal_detail', attributes: ['doj'] }, { association: 'employee_office_detail', attributes: ['reporting_manager_id'] }]
      });

      if (user == null || !user)
        throw new CustomUnauthorizedException(
          "Warning! The provided Employee ID or Email is incorrect. Please check and try again.",
          HttpStatus.BAD_REQUEST
        );

      if (device_type == 'mobile') {
        if (user.user_code == null || user.user_code == '') {
          return await responseMessageGenerator(
            "failure",
            "Oops ! Employee code is required for mobile logins.",
            ''
          );
        }
      }

      if (!user)
        throw new CustomUnauthorizedException(
          "Warning! The provided Employee ID or Email is incorrect. Please check and try again.",
          HttpStatus.BAD_REQUEST
        );
      if (user && is_google_login === false && (user.user_password === null || user.user_password === '')) {
        throw new CustomUnauthorizedException(
          "Attention! You have signed in with Google. Please try signing in with Google again or reset your password to proceed with normal sign-in",
          HttpStatus.BAD_REQUEST
        );
      }

      let comparing = false
      if (user_password) {
        comparing = compareSync(user_password, user.user_password);
      }
      let getCacheData = await this.RedisService.getCacheValue('login_wrong_attempts_' + user.user_code)
      if (getCacheData >= this.MAX_ATTEMPTS) {
        throw new CustomLoginfaiedException(
          "Attention! You have made multiple attempts with an invalid password. Please reset your password using the Forgot Password option1.",
          null,
          { 'isLoginAttemptsExceed': false },

        );
      }
      if (!comparing && is_google_login === false) {

        let isLoginAttemptsExceed = { 'isLoginAttemptsExceed': false };

        /* check multiple login attempts with wrong password  stored in redis */

        const attempts = await this.RedisService.getCacheValue('login_wrong_attempts_' + user.user_code) || 0;
        const saveCacheData = await this.RedisService.setCacheValue('login_wrong_attempts_' + user.user_code, attempts + 1, 0)

        throw new CustomUnauthorizedException(
          "Warning! The provided password is incorrect. Please check and try again.",
          HttpStatus.BAD_REQUEST
        );

      }

      if (user.is_owner) {
        condition['is_active'] = true
      } else {
        user.is_onboard && (condition['is_active'] = true)
      }

      const isActive = await this.userRepository.findOne({ where: condition });

      if (!isActive) {
        throw new CustomUnauthorizedException('Invalid user. Please contact the HR Team for further details', HttpStatus.BAD_REQUEST);
      }
      if (fcm_tokens?.value) {
        await this.updateUserFcmToken(user.id, fcm_tokens)
      }

      let planData = null;
      if (user?.client_id) {
        planData = await this.ClientCompanyModel.findOne({
          where: { id: user?.client_id },
          attributes: ['id', 'subscription_plan_id', 'is_welcome_completed', 'industry_type', "company_start_date", 'hr_admin', 'finance_admin']
        });
      }

      const checkIsFinanceAdmin = planData?.finance_admin?.find((financeAdmin) => financeAdmin?.user_id === user?.id);
      const checkIsHrAdmin = planData?.hr_admin?.find((hrAdmin) => hrAdmin?.user_id === user?.id);

      const accessTokenPayload = {
        user_id: user.id,
        domain_id: user.domain_id,
        user_name: user.user_name,
        user_code: user.user_code,
        user_email: user.user_email ?? null,
        client_id: user.client_id,
        is_active: user.is_active,
        is_onboard: user.is_onboard,
        is_owner: user.is_owner,
        user_role: user?.user_role_id || null,
        onboard_type: user.onboard_type,
        active_status: user.status,
        reporting_manager_id: user?.employee_office_detail?.reporting_manager_id,
        is_default_password_updated: user.is_default_password_updated,
        plan_id: planData?.subscription_plan_id,
        company_start_year: planData?.company_start_date ? moment(planData.company_start_date).format('YYYY') : null,
        org_type: planData?.industry_type ? planData?.industry_type?.replace(/Shop & Establishment/g, "Shop and Establishment") : null,
        doj: user?.employee_personal_detail?.doj,
        additional_role: {
          is_hr_admin: checkIsHrAdmin ? true : false,
          is_finance_admin: checkIsFinanceAdmin ? true : false,
        }
      };
      const accessToken = await this.jwtService.signAsync(accessTokenPayload, {
        expiresIn: "1h",
        secret: jwtConstants.secret,
      });
      const refreshToken = await this.jwtService.signAsync(accessTokenPayload, {
        expiresIn: "7d",
        secret: jwtConstants.secret,
      });

      const redirection_route: any = {};
      if (user) {
        if (user.is_owner) {
          redirection_route.is_owner = 1;
          (!(await this.checkExistingDomainCompany(user.domain_id))) && (redirection_route.is_not_company_created = 1);
          ((await this.checkExistingDomainCompany(user.domain_id)) && (!planData?.is_welcome_completed)) && (redirection_route.is_not_welcome_completed = 1);
          ((user.is_onboard && !user.is_default_password_updated) && (redirection_route.is_not_reset_password = 1));
        } else {
          redirection_route.is_owner = 0;
          (!user.is_default_password_updated) && (redirection_route.is_not_reset_password = 1);
          ((!user.is_onboard && (user.onboard_type == 'bulk')) || (user.is_onboard && ((user.onboard_type == 'bulk') && user.status == 0 && (await this.employeeRejectedSomeOnboardingDocuments(user.id))))) && (redirection_route.is_not_bulk_onboarding = 1);
          ((!user.is_onboard && (user.onboard_type == 'quick')) || (user.is_onboard && ((user.onboard_type == 'quick') && user.status == 0 && (await this.employeeRejectedSomeOnboardingDocuments(user.id))))) && (redirection_route.is_not_quick_onboarding = 1);
          (user.is_onboard && (user.status == 0 && (!await this.employeeRejectedSomeOnboardingDocuments(user.id)))) && (redirection_route.is_not_doc_reviewed = 1);
        }
      }

      const data = {
        access_token: accessToken,
        refresh_token: refreshToken,
        user: {
          user_code: user.user_code,
          user_email: user.user_email ?? null,
          user_name: user.user_name,
        },
        ...redirection_route
      };
      await this.activityLogService.createActivity({
        domain_id: user.domain_id,
        client_id: user.client_id,
        user_id: user.id,
        model: 'user',
        action: 'login',
        description: `${user.user_name} logged in`,
        log_type: LogType.Authentication
      })
      // if (fcm_tokens?.value) {
      //   this.pushNotifications(user.id, 'Authentication', 'Logged in successfully')
      // }
      this.updateUserEntry(user.id, device_type)

     const  cookie = await this.cloudFrontService.generateSignedCookieFromFile(req,res)

      if(cookie){
      return await responseMessageGenerator(
        "success",
        "Logged in successfully",
        data
      );
    }
    
    } catch (error) {
      console.error("Error during sign-in:", error.message);
      throw new CustomUnauthorizedException(error.message, error.status);
    }
  }
