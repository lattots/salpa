export class AuthService {
	authDomain: string = "";
	providers: string[] = [];

	async refreshAccessToken(): Promise<void> {
		const resp: Response = await fetch(`${this.authDomain}/auth/refresh`);
		// Refresh token expired -> User needs to login again
		if (resp.status === 401) {
			throw Error(`refresh token expired`);
		}

		// Unexpected error refreshing token
		if (!resp.ok) {
			throw Error(`failed to refresh access token: ${resp.status} - ${resp.statusText}`);
		}
	}
}
