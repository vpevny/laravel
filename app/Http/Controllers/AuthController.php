<?php

namespace App\Http\Controllers;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Dotenv\Exception\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request){
        try {
            $postFields = $request->validate([
                'name' => 'required',
                'email' => 'required', 
                'password' => ['required', 'min:5', 'confirmed']
            ]);
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
            $token = $user->createToken('auth_token')->plainTextToken;

            return (response()->json(['access_token' => $token, 'token_type' => 'Bearer']));

        } catch (ValidationException $e) {
            // chyba při validaci
            return response()->json(['error' => 'Validation failed', 'messages' => $e->getMessage()], 422);
        } catch (Exception $e) {
            // jiná chyba
            return response()->json(['error' => 'Registration failed', 'message' => $e->getMessage()], 400);
        }
        }
    public function login(Request $request){
        try {
            $request->validate([
                'email' => 'required|email',
                'password' => 'required',
            ]);

            $user = User::where('email', $request->email)->first();

            if (!Auth::attempt($request->only('email', 'password'))) {
                throw ValidationException::withMessages([
                    'email' => ['The provided credentials are incorrect.'],
                ]);
            }
            // token
            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user name' => $user->name, 
                'user email' => $user->email]);

            } catch (Exception $e) {
                return response()->json(['error' => 'Logging in failed', 'message' => $e->getMessage()]);
            }
        }
    public function logout()
        {
            Auth::user()->tokens()->delete();
            return response()->json([
                'message' => 'logged out',
            ]);
        }
}
