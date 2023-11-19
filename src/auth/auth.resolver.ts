import { BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { LoginResponse, RegisterResponse } from './types';
import { RegisterDto, LoginDto } from './dto';
import { response, Response, Request } from 'express';

@Resolver()
export class AuthResolver {
    constructor(private readonly authService: AuthService ) { }


    @Mutation(() => RegisterResponse)
    async register(
        @Args('registerInput') registerDto: RegisterDto,
        @Context() context: { res: Response }) {
        if (registerDto.password !== registerDto.confirmPassword) {
            throw new BadRequestException({
                confirmPassword: 'Password and cnfirm password are notr the same'
            })
        }
        const { user } = await this.authService.register(registerDto, context.res)
        return { user }
    }



    @Mutation(() => LoginResponse)
    async login(
        @Args('loginInput') loginDto: LoginDto,
        @Context() context: { res: Response },

    ) {
        return this.authService.login(loginDto, context.res)
    }


    @Mutation(() => String)
    async logout(
        @Context() context: { res: Response },

    ) {
        return this.authService.logout(context.res)
    }

    @Mutation(() => String)
    async refreshToken(
        @Context() context: { req: Request, res: Response },

    ) {
        try {
            return this.authService.refreshToken(context.req, context.res)
        } catch (error) {
            throw new BadRequestException(error.message)

        }

    }



    @Query(() => String)
    async hello() {
        return "hello";
    }
}
