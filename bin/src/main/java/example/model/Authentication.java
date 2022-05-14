package example.model;

public class Authentication {

	private String username;
	private String password;
	private example.security.Encode encode;

	public Authentication() {
		encode = new example.security.Encode();

		this.username = "user";
		this.password = encode.hashpw("pass");
	}

	private String getUsername(){
		return this.username;
	}

	private String getPassword(){
		return this.password;
	}

	public Boolean authenticate(String username, String password){
		boolean t = encode.verify(password, this.password);
		if(username.equals(getUsername()) && t){
			return true;
		}
		return false;
	}

}
