


package body KOW_Sec.Authentication.Entities is

	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------

	function Do_Login(	Manager:  in Authentication_Manager;
				Username: in String;
				Password: in String ) return User'Class is
		-- Login the user, returning a object representing it.
		-- This object might be a direct instance of User or a subclass.
		-- It's this way so the authentication method might have
		-- a user with extended properties.
		use User_Query_Builders;

		Q : Query_Type;
	begin
		Append(
				Q		=> Q,
				Column		=> "username",
				Value		=> Username,
				Appender	=> Appender_AND,
				Operator	=> Operator_Equals
			);

		Append_Password(
				Q		=> Q,
				Column		=> "password",
				Value		=> Password,
				Appender	=> Appender_AND,
				Operator	=> Operator_Equals
			);
		return To_User( Get_First( Q => Query, Unique => True ) );
	exception
		when NO_ENTITY =>
			raise KOW_Sec.INVALID_CREDENTIALS with "Login for the user """ & Username & """ failed!";
	end Do_Login;


	function Get_Groups(	Manager:	in Authentication_Manager;
				User_Object:	in User'Class )
				return Authorization_Groups is
		-- Return all the groups for this user in _this_ manager.
		-- This function is called by the Groups_Cache_Type's method Update.
		-- It's implemented in the manager for 2 reasons:
		-- 	1. this way we can store the users and the groups in
		-- 	  different managers.
		-- 	2. the information on how to obtain the groups information
		-- 	  doesn't belong to the user itself.
		-- When implementor of this method should assume:
		-- 	1. the user is valid and so is the results of Identity( User_Object );
		-- 	2. it's meant to work with any authentication manager vs user combination.
		-- This is a private method so the user won't call it directly.
		-- Instead, it's called by the Get_Groups (User'Class) method implemented here.
	begin
	end Get_Groups;

end KOW_Sec.Authentication.Entities;
