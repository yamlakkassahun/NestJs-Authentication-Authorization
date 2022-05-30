import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Auth, AuthDocument } from '../entities/auth.entity';
import * as bcrypt from 'bcrypt';
import { from, Observable, of } from 'rxjs';
import { catchError, map, switchMap, tap } from 'rxjs/operators';
import { UpdateAuthDto } from '../dto/update-auth.dto';
import { Role } from '../entities/role.enum';
import { CreateAuthDto } from '../dto/create-auth.dto';
import { UpdatePasswordDto } from '../dto/update-password.dto';

@Injectable()
export class AuthService {
  authModel: any;
  constructor(
    @InjectModel(Auth.name) private userModel: Model<AuthDocument>,
    private jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 12);
  }

  async doesUserExist(email: string): Promise<any> {
    await this.userModel.findOne({ email }).then((user: Auth) => {
      if (user) {
        return true;
      }
    });
    return false;
  }

  async registerAccount(user: CreateAuthDto): Promise<Auth> {
    const { email, password, address, firstName, lastName, phone, role } = user;
    const userExist: boolean = await this.doesUserExist(email);

    //check if there is a user with this email
    if (userExist) {
      throw new HttpException(
        'A user has already been created with this email address',
        HttpStatus.BAD_REQUEST,
      );
    }

    //assigning Role
    let userRole = Role.USER;
    if (role === 'admin') {
      userRole = Role.ADMIN;
    } else if (role === 'super') {
      userRole = Role.SUPER;
    }

    //hashing the password
    const hashedPassword = await this.hashPassword(password);

    //registering the new user and returning it
    return this.userModel.create({
      firstName,
      lastName,
      email,
      address,
      phone,
      role: userRole,
      password: hashedPassword,
    });
  }

  async validateUser(email: string, password: string): Promise<Auth> {
    const existingUser = await this.userModel.findOne({ email });

    //check if the user exist
    if (!existingUser) {
      throw new HttpException(
        { status: HttpStatus.FORBIDDEN, error: 'Invalid Credentials' },
        HttpStatus.FORBIDDEN,
      );
    }

    //check the users password
    if (!(await bcrypt.compare(password, existingUser.password))) {
      throw new HttpException(
        { status: HttpStatus.FORBIDDEN, error: 'Invalid Credentials' },
        HttpStatus.FORBIDDEN,
      );
    }

    return existingUser;
  }

  async login(userCredentials: Auth): Promise<string> {
    const { email, password } = userCredentials;
    const user = await this.validateUser(email, password);

    if (user) {
      // create JWT - credentials
      return this.jwtService.signAsync({ user });
    }
  }

  getJwtUser(jwt: string): Observable<Auth | null> {
    return from(this.jwtService.verifyAsync(jwt)).pipe(
      map(({ user }: { user: Auth }) => {
        return user;
      }),
      catchError(() => {
        return of(null);
      }),
    );
  }

  findAllUsers(): Observable<Auth[] | any> {
    return from(this.userModel.find());
  }

  findUserById(id: string): Observable<Auth> {
    return from(this.userModel.findById(id)).pipe(
      map((user) => {
        if (!user) {
          throw new HttpException(
            { status: HttpStatus.FORBIDDEN, error: 'User Was Not Found' },
            HttpStatus.FORBIDDEN,
          );
        }
        return user;
      }),
    );
  }

  async registerUser(user: Auth): Promise<Auth> {
    const { email, password, address, firstName, lastName, phone, role } = user;
    const userExist: boolean = await this.doesUserExist(email);

    //check if there is a user with this email
    if (userExist) {
      throw new HttpException(
        'A user has already been created with this email address',
        HttpStatus.BAD_REQUEST,
      );
    }

    //assigning Role
    let userRole = Role.USER;
    if (role === 'admin') {
      userRole = Role.ADMIN;
    } else if (role === 'super') {
      userRole = Role.SUPER;
    }

    //hashing the password
    const hashedPassword = await this.hashPassword(password);

    //registering the new user and returning it
    return this.userModel.create({
      firstName,
      lastName,
      email,
      address,
      phone,
      role: userRole,
      password: hashedPassword,
    });
  }

  async updateUser(id: string, user: UpdateAuthDto): Promise<Auth> {
    const { email, password, address, firstName, lastName, phone, role } = user;

    //hashing the password
    const hashedPassword = await this.hashPassword(password);

    //find the user by id
    const existingUser = await this.userModel.findById(id);

    //check if the user exist
    if (!existingUser) {
      throw new HttpException(
        { status: HttpStatus.FORBIDDEN, error: 'User Was Not Found' },
        HttpStatus.FORBIDDEN,
      );
    }

    //adding the role
    let userRole = Role.USER;
    if (role === 'admin') {
      userRole = Role.ADMIN;
    } else if (role === 'super') {
      userRole = Role.SUPER;
    }

    //update the values and returning them
    existingUser.email = email;
    existingUser.password = hashedPassword;
    existingUser.address = address;
    existingUser.firstName = firstName;
    existingUser.lastName = lastName;
    existingUser.role = userRole;
    existingUser.phone = phone;
    await existingUser.save();

    //returning the user
    return existingUser;
  }

  //password update
  async ChangePassword(
    user: any,
    updatePasswordDto: UpdatePasswordDto,
  ): Promise<Auth> {
    const { oldPassword, newPassword } = updatePasswordDto;
    const existingUser = await this.userModel.findById(user._id);
    //check if the old password is correct
    if (!existingUser && bcrypt.compare(oldPassword, existingUser.password)) {
      throw new HttpException(
        { status: HttpStatus.FORBIDDEN, error: 'User Was Not Found' },
        HttpStatus.FORBIDDEN,
      );
    }

    //hashing the password
    const hashedPassword = await this.hashPassword(newPassword);

    existingUser.password = hashedPassword;
    await existingUser.save();
    return existingUser;
  }

  deleteUser(id: string): Observable<Auth> {
    return from(this.userModel.findByIdAndDelete(id));
  }
}
