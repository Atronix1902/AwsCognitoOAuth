<?php

use App\Models\User;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Illuminate\Database\QueryException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AwsToken
{
    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @return JsonResponse
     */
    public function handle(Request $request, Closure $next): JsonResponse
    {
        //Create AWS Clients
        $cognito = new CognitoIdentityProviderClient([
            'credentials'   => [
                'key'       => env('AWS_ACCESS_KEY_ID'),
                'secret'    => env('AWS_SECRET_ACCESS_KEY')
            ],
            'version'       => env('AWS_COGNITO_VERSION'),
            'region'        => env('AWS_COGNITO_REGION'),
            'userpool'      => env('AWS_COGNITO_USER_POOL_ID')
        ]);

        //Get User by OAuth2 Token
        try {
            //Get Cognito user
            $data = $cognito->getUser([
                'AccessToken' => str_replace('Bearer ', '', $request->header('Authorization')),
            ]);
            //Get local database user
            $userid = collect($data['UserAttributes'])->firstWhere('Name', '=', 'sub')['Value'];
            $user = User::where(['cognito_user_id' => $userid])->first();

            // Create User if not found in database (SSO)
            if (!($user instanceof User)) {
                $user = new User();
                $user->cognito_user_id = $userid;
                $user->username = $data['Username'];
                $user->save();
            }
        } //Catch AWS Error
        catch (AwsException $exception) {
            return response()->json([
                'message' => $exception->getAwsErrorMessage()
            ])->setStatusCode(401);
        } //Catch Query Error
        catch (QueryException $exception) {
            if ($exception->getCode() == 1054) {
                // Create User if not found in database (SSO)
                $user = new User();
                $user->username         = $data['Username'];
                $user->cognito_user_id  = $userid;
                $user->save();
            } else {
                return response()->json([
                    'code' => $exception->getCode(),
                    'message' => $exception->getMessage()
                ]);
            }
        }

        auth()->setUser($user);
        return $next($request);
    }
}