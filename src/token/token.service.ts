import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';
import { verify } from 'jsonwebtoken';

@Injectable()
export class TokenService {

    constructor(private configService: ConfigService) { }
    extractToken(connectionsParams: any): string | null {
        return connectionsParams?.token || null
    }

    validateToken(token: string): any {
        const refreshTokenSecret = this.configService.get<string>(
            'REFRESH_TOKEN_SECRET'
        );
        try {
            return verify(token, refreshTokenSecret)
        } catch (error) {
            return null

        }
    }

}
