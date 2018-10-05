<?php

	namespace App\Http\Controllers;

	use \http\Env\Response;
	use \Illuminate\Http\Request;
	use \Illuminate\Support\Facades\DB;
	use \Illuminate\Support\Facades\Hash;
	use \Laravel\Lumen\Routing\Controller as BaseController;

	class LoginController extends BaseController
	{

		public $result =  [];
		public $request =  [];


		/**
		 * @param  Request  $request
		 * @return Response
		 */
		public function user(Request $request)
		{
			$validation = $this->validate($request, [
				'username' => 'required',
				'password' => 'required|min:8'
			]);

			$user = DB::connection('mysql.read')
					  ->table('users')
					  ->where('username','=',$request->input('username'))
					  ->where('username_hash','=',sha1($request->input('username')))
					  ->first();


			if($user !== NULL){
				if (Hash::check($request->input('password'), $user->password))
				{
					$token = bin2hex(openssl_random_pseudo_bytes(64));

					// Add Token for User

					return response()->json([
						'result' => [
							'status' => 'success',
							'message' => 'User authenticated.',
							'token' => $token
						],
						'request' => [
							'username' => $request->input('username')
						],
					]);
				}
				else{
					return response()->json([
						'result' => [
							'status' => 'warning',
							'message' => 'User credentials wrong.',
							'token' => $token
						]
					]);
				}
			}

			return response()->json([
				'result' => [
					'status' => 'error',
					'message' => 'User doesnt exists.'
				]
			]);
		}
	}
