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

import { Component, OnInit } from '@angular/core';
import { AuthorizationService } from '../authorization.service';
import { UserInfo } from '../userinfo';
import { TokenResponse } from '@openid/appauth';

@Component({
  selector: 'app-authentication',
  templateUrl: './authentication.component.html',
  styleUrls: ['./authentication.component.scss']
})
export class AuthenticationComponent implements OnInit {

  public userInfo: UserInfo | null;
  public authorized: boolean;
  public requestedContent = {};
  public requestedSensitiveContent = {};

  constructor(private authorizationService: AuthorizationService) {
  }

  ngOnInit() {
    this.authorizationService.userInfos().subscribe((userInfo: UserInfo) => {
      this.userInfo = userInfo;
    });
    this.authorizationService.tokenResponse().subscribe((tokenResponse: TokenResponse) => {
      this.authorized = tokenResponse != null;
    });
	this.authorizationService.requestedContents().subscribe((requestedContent: string) => {
      this.requestedContent = requestedContent;
    });
	this.authorizationService.requestedSensitiveContents().subscribe((requestedSensitiveContent: string) => {
      this.requestedSensitiveContent = requestedSensitiveContent;
    });
  }
}
