import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserService } from '../user/user.service';
import { User } from '../user/user.entity';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private userService: UserService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: async (request, rawJwtToken, done) => {
        try {
          const payload = this.decodeToken(rawJwtToken);
          const user = await this.userService.findByEmail(payload.email);
          if (user) {
            done(null, user.jwtSecret); // Use user's secret
          } else {
            done(new UnauthorizedException(), null);
          }
        } catch (error) {
          done(new UnauthorizedException(), null);
        }
      },
    });
  }

  private decodeToken(token: string): any {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
  }

  async validate(payload: any): Promise<User> {
    const user = await this.userService.findByEmail(payload.email);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
