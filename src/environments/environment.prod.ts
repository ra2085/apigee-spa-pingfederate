// Copyright 2018 Ping Identity
//
// Licensed under the MIT License (the "License"); you may not use this file
// except in compliance with the License.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// NOTE these are the production values for the SPA as deployed on Heroku.
// You will need to create your own production configuration to deploy
// into your environment.
import { AuthorizationConfig, GeneralEnvironmentInfo } from '../app/authorization_config';

export const environment: AuthorizationConfig & GeneralEnvironmentInfo = {
  production: true,
  issuer_uri: 'https://gonzalezruben-eval-test.apigee.net/ping_apigee_oauth'
  client_id: 'client_a',
  redirect_uri: 'https://4200-dot-4427029-dot-devshell.appspot.com/callback',
  extras: {
   'prompt': 'consent',
    'access_type': 'offline',
	'pfidpadapterid': 'test'
  }
};
