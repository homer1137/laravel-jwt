<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Validation\Rules\Password;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|max:255',
            'email' => 'required|unique:users|email',
            'password' => ['required', 'string', Password::min(5)->letters()->numbers()->mixedCase()]
        ]);
        if($validator->fails()){
           return response()->json($validator->errors()->toJson(),400);
        }


        $user = User::create([
            'name'=>$request->input('name'),
            'email'=>$request->input('email'),
            'password'=> Hash::make($request->input('password')),
        ]);
        return $user;
    }

    public function login (Request $request){
       if(!Auth::attempt(
        ['email'=>$request->input('email'),
        'password'=> $request->input('password')]
       )){
            return response(
                ['message'=>'Invalid credentials!'], Response::HTTP_UNAUTHORIZED
            );
       }

       $user = Auth::user();
   /** @var \App\Models\MyUserModel $user **/
       $token =$user->createToken('token')->plainTextToken;

       $cookie = cookie('jwt', $token, 60*24);

       return response(
        ['message' => $token]
       )->withCookie($cookie);

    }

    public function user () {
        return Auth::user();
    }

    public function logout () {
        $cookie = Cookie::forget('jwt');

        return response([
            'message'=>'Success logout'
        ])->withCookie($cookie);
    }
}
