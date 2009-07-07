

---------------
-- Ada Works --
---------------
with KOW_Ent;
with KOW_Ent.Query_Builders;
with KOW_Sec;


package KOW_Sec.Authentication.Entities is


	----------------------
	-- USER ENTITY TYPE --
	----------------------

	type User_Entity_Type is new KOW_Ent.Entity_Type with private;
	-- This represents the user data in the data base
	-- The ID for this entity is the Hash code for the username
	--
	-- This is how we make sure each user name is unique.


	overriding
	function To_String( Entity : in User_Entity_Type ) return String;
	-- return the user identity

	
	function To_User( Entity : in User_Entity_Type ) return KOW_Sec.User;
	-- convert the entity to an KOW_sec.user type

	function To_User_Entity( Entity : in KOW_Sec.User'Class ) return User_Entity_Type;
	-- convert the user type to an user entity type
	-- assumes the user is already in the database.


	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------

	type Authentication_Manager is KOW_Sec.Authentication_Manager with private;
	-- This is where the magic happens!
	--
	-- The Authentication_Manager type is the type that should be extended
	-- when a new authentication method is implemented.
	--
	-- It's a controlled type only for the pleasure of the type implementor.


	function Do_Login(	Manager:  in Authentication_Manager;
				Username: in String;
				Password: in String ) return User'Class;
	-- Login the user, returning a object representing it.
	-- This object might be a direct instance of User or a subclass.
	-- It's this way so the authentication method might have
	-- a user with extended properties.



	function Get_Groups(	Manager:	in Authentication_Manager;
				User_Object:	in User'Class )
				return Authorization_Groups;
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




	package User_Query_Builders is new KOW_Ent.Query_Builders( Entity_Type => User_Entity_Type );

private
	type Authentication_Manager is KOW_Sec.Authentication_Manager with null record;

end KOW_Sec.Authentication.Entities;
