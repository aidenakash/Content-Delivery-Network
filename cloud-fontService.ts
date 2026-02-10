import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import * as AWS from 'aws-sdk';
import { Signer } from 'aws-sdk/clients/cloudfront';
import { promises as fs } from 'fs';
import { awsAccountConfig } from 'src/app.constants';

@Injectable()
export class CloudFrontService {

    private readonly secretsManager: AWS.SecretsManager;
    private readonly logger = new Logger(CloudFrontService.name);
    private readonly awsAccountConfigdata = awsAccountConfig;


    constructor() {
        this.secretsManager = new AWS.SecretsManager();
    }

    /**
     * Retrieves the private key from AWS Secrets Manager
     */
    async getPrivateKeyFromSecretsManager(): Promise<string> {
        try {

              const secret = await this.secretsManager.getSecretValue({
                SecretId: 'CloudFrontPrivateKey',
              }).promise();

              if (!secret.SecretString) {
                throw new Error('SecretString is empty');
              }

              return secret.SecretString;

            

        } catch (error) {
            this.logger.error('Error fetching private key from AWS Secrets Manager', error);
            throw new InternalServerErrorException('Failed to retrieve private key');
        }
    }


    /**
     * Retrieves the private key from a local file
     */
    async getPrivateKeyFromFile(): Promise<string> {
        try {

            const filePath = 'D:/hrms/hrms-backend/private_key.pem'; // Use forward slashes or double backslashes

            return await fs.readFile(filePath, 'utf8');

        } catch (error) {
            this.logger.error('Error reading private key file', error);
            throw new InternalServerErrorException('Failed to retrieve private key from file');
        }
    }


    /**
     * Generates signed cookies using the private key from AWS Secrets Manager
     */
      async generateSignedCookieFromSecretsManager(req: any, res: any) {

        const privateKey = await this.getPrivateKeyFromSecretsManager();

        return this.generateSignedCookie(privateKey, req, res);

      }



    /**
     * Generates signed cookies using the private key from a local file
     */
    async generateSignedCookieFromFile(req: any, res: any) {

        const privateKey = await this.getPrivateKeyFromFile();

        return this.generateSignedCookie(privateKey, req, res);

    }



    /**
     * Generates signed cookies with a given private key
     */
    private generateSignedCookie(privateKey: string, req: any, res: any) {

        const signer = new Signer(this.awsAccountConfigdata.cloudfrontDevPublicKey, privateKey);

        // Use a custom policy to include `CloudFront-Policy`
        const policy = JSON.stringify({
            Statement: [
                {
                    Resource: 'https://d2s93q2vmyucuf.cloudfront.net/public/*',
                    Condition: {
                        DateLessThan: { 'AWS:EpochTime': Math.floor(Date.now() / 1000) + 60 * 60 }, // 1-hour validity
                    },
                    IpAddress: {
                        "AWS:SourceIp": req.headers['x-forwarded-for'] || req.socket.remoteAddress //req.ip || req.connection.remoteAddress || 
                    },
                    StringEquals: {
                        "AWS:UserAgent": req.headers['user-agent']
                    }
                },
            ],
        });

        const cookies = signer.getSignedCookie({ policy }); // This ensures `CloudFront-Policy` is generated

        if (!cookies || !cookies['CloudFront-Policy'] || !cookies['CloudFront-Key-Pair-Id'] || !cookies['CloudFront-Signature']) {
            throw new InternalServerErrorException('Missing required CloudFront signed cookies');
          }

           const domain = 'd2s93q2vmyucuf.cloudfront.net';
           const maxAge = 60 * 60 * 1000; // 1 hour

        // Set signed cookies
        res.cookie('CloudFront-Policy', cookies['CloudFront-Policy'], {
            httpOnly: true,
            secure: true,
            domain,
            maxAge,
        });

        res.cookie('CloudFront-Key-Pair-Id', cookies['CloudFront-Key-Pair-Id'], {
            httpOnly: true,
            secure: true,
            domain,
            maxAge
        });

        res.cookie('CloudFront-Signature', cookies['CloudFront-Signature'], {
            httpOnly: true,
            secure: true,
            maxAge,
            domain
        });

        this.logger.debug('Signed Cookie Set!', );
        return cookies; 

    }

}
