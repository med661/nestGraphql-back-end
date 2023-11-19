import {
    Injectable,
    UnauthorizedException,
    BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma.service';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { User } from 'src/user/user.type';
import { LoginDto, RegisterDto } from './dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
    ) { }

    async refreshToken(req: Request, res: Response) {
        const refreshToken = req.cookies['refresh_token'];
        if (!refreshToken) {
            throw new UnauthorizedException('refreshToken not found');
        }
        let payload;
        try {
            payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.get(<string>'REFRESH_TOKEN_SECRET'),
            });
        } catch (error) {
            throw new UnauthorizedException('Invalid or expired refresh token ');
        }
        const userExists = await this.prisma.user.findUnique({
            where: { id: payload.sub },
        });
        if (!userExists) {
            throw new BadRequestException('user no longer exist');
        }

        const expiresIn = 15000;
        const expiration = Math.floor(Date.now() / 1000) + expiresIn;

        const acccessToken = this.jwtService.sign(
            { ...payload, exp: expiration },
            { secret: this.configService.get(<string>'ACCESS_TOKEN_SECRET') },
        );

        res.cookie('access_token', acccessToken, { httpOnly: true });
        return acccessToken;
    }
    private async issueTokens(user: User, response: Response) {
        const payload = { username: user.fullname, sub: user.id };
        const acccessToken = this.jwtService.sign(
            { ...payload },
            {
                secret: this.configService.get(<string>'ACCESS_TOKEN_SECRET'),
                expiresIn: '150sec',
            },
        );

        const refreshToken = this.jwtService.sign(payload, {
            secret: this.configService.get(<string>'REFRESH_TOKEN_SECRET'),
            expiresIn: '7d',
        });

        response.cookie('access_token', acccessToken, { httpOnly: true });
        response.cookie('refresh_token', refreshToken, { httpOnly: true });
        return { user };
    }

    async ValidateUser(loginDto: LoginDto) {
        const user = await this.prisma.user.findUnique({
            where: { email: loginDto.email }
        })
        if (user && (await bcrypt.compare(loginDto.password, user.password))) {
            return user;
        }
        return null;
    }

    async register(registerDto: RegisterDto, response: Response) {
        const userExists = await this.prisma.user.findUnique({
            where: { email: registerDto.email },
        });
        if (!userExists) {
            throw new BadRequestException({ email: 'Email already in used' });
        }
        const hashedPassword = await bcrypt.hash(registerDto.password, 10)
        const user = await this.prisma.user.create({
            data: {
                fullname: registerDto.fullname,
                password: hashedPassword,
                email: registerDto.email
            }
        })


        return this.issueTokens(user, response)
    }
    async login(loginDto: LoginDto, response: Response) {
        const user = await this.ValidateUser(loginDto);
        if (!user) {
          throw new BadRequestException({
            invalidCredentials: 'Invalid credentials',
          });
        }
        return this.issueTokens(user, response);
      }
      async logout(response: Response) {
        response.clearCookie('access_token');
        response.clearCookie('refresh_token');
        return 'Successfully logged out';
      }

}
