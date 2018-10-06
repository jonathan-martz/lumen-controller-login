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

		public function addResult(string $key, $value):void{
			$this->result[$key] = $value;
		}

		public function addRequest(string $key, $value):void{
			$this->result[$key] = $value;
		}

		public function getResponse(){
			return response()->json([
				'result' => $this->result,
				'request' => $this->request
			]);
		}

		/**
		 * @param  Request  $request
		 * @return Response
		 */
		public function user(Request $request){
			$validation = $this->validate($request, [
				'username' => 'required',
				'password' => 'required|min:8'
			]);

			$user = DB::connection('mysql.read')
					  ->table('users')
					  ->where('username', '=', $request->input('username'))
					  ->where('username_hash', '=', sha1($request->input('username')))
					  ->first();

			$trys = DB::connection('mysql.read')
					  ->table('login_try')
					  ->where('username', '=', $request->input('username'))
					  ->where('username_hash', '=', sha1($request->input('username')))
					  ->whereNotIn('status' , ['success'])
					  ->where('created_at','<',time() - (60 * 60))
					  ->count();

			if($trys < 10){
				if($user !== NULL){
					if (Hash::check($request->input('password'), $user->password))
					{
						$token = bin2hex(openssl_random_pseudo_bytes(512));

						DB::connection('mysql.write')
						  ->table('login_try')
						  ->insert([
							  'username' => $request->input('username'),
							  'username_hash' => sha1($request->input('username')),
							  'status' => 'success',
							  'created_at' => time()
						  ]);

						DB::connection('mysql.write')
						  ->table('auth_tokens')
						  ->insert([
							  'token' => $token,
							  'UID' => $user->id,
							  'created_at' => time()
						  ]);

						// Extend Controller from CustomController
						// Add custom controller as requirement
						// create module for CustomController

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
						DB::connection('mysql.write')
						  ->table('login_try')
						  ->insert([
							  'username' => $request->input('username'),
							  'username_hash' => sha1($request->input('username')),
							  'status' => 'failed',
							  'created_at' => time()
						  ]);

						return response()->json([
							'result' => [
								'status' => 'warning',
								'message' => 'User credentials wrong.'
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
			else{
				DB::connection('mysql.write')
				  ->table('login_try')
				  ->insert([
					  'username' => $request->input('username'),
					  'username_hash' => sha1($request->input('username')),
					  'status' => 'blocked',
					  'created_at' => time()
				  ]);

				return response()->json([
					'result' => [
						'status' => 'error',
						'message' => 'User login blocked.'
					]
				]);
			}
		}
	}
