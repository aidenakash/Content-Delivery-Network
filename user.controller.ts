@Post("sign-in")
  async signIn(@Body() createUserDto: SignInDto) {
    const signInResult = await this.authenticationService.signIn(createUserDto.domain_id, createUserDto.user_code, createUserDto.user_password, createUserDto.fcm_token, createUserDto.is_google_login);
    // Return the result to the client immediately
    // setImmediate(() => {
    //   // Execute the attendance function after 5 seconds
    //   setTimeout(() => {
    //     this.attendanceService.saveCheckinImmediate(createUserDto.user_code);
    //   }, 5000);
    // });
    return signInResult;
  }

 @Get('generate-cookie')
  /**
   * Generates signed cookies for CloudFront using the private key from a local file.
   * The signed cookies are set in the response.
   * @param res The response object to set the signed cookies in.
   * @param req The request object containing the domain name and other necessary information.
   */
  async generateCookie(@Res() res: any, @Req() req: any) {
    try {
      //AWS Secrets manager
      //const cookies = await this.cloudFrontService.generateSignedCookieFromS
      // ecretsManager();

      //Local Aws Accoutn Config
      const cookies = await this.cloudFrontService.generateSignedCookieFromFile(req,res);

      res.status(200).send({staus:'Signed Cookie Set!',cookies});

    } catch (error) {
      console.error('Error generating signed cookies', error);
      throw new InternalServerErrorException('Failed to generate signed cookies');
    }
  }
