


--------------
-- Ada 2005 --
--------------
with Ada.Strings.Unbounded;		use Ada.Strings.Unbounded;


---------------
-- Ada Works --
---------------
with KOW_Ent;
with KOW_Ent.Query_Builders;
with KOW_Sec;				use KOW_Sec;


package KOW_Sec_Entities is


	----------------------
	-- USER ENTITY TYPE --
	----------------------

	type User_Entity_Type is new KOW_Ent.Entity_Type with record
		User_Identity	: User_Identity_Type;
		Username	: Unbounded_String;
		Password	: Unbounded_String;
		-- well, we need some place to store user's password, don't we?
	end record;

	
	overriding
	function To_String( Entity : in User_Entity_Type ) return String;
	-- return the user identity


	overriding
	function Describe( Entity : in User_Entity_Type ) return String;
	-- return the full name of the user
	
	overriding
	function Image_URL( Entity : in User_Entity_Type ) return String;
	-- get the gravatar for the given user


	
	function To_User( Entity : in User_Entity_Type ) return User_Type;
	-- convert the entity to an KOW_sec.user type

	function To_User_Entity( User : in User_Type ) return User_Entity_Type;
	-- convert the user type to an user entity type
	-- assumes the user is already in the database.

	function Get_user_Entity( Username: in String ) return User_Entity_Type;
	-- get the user entity by it's username

	package User_Query_Builders is new KOW_Ent.Query_Builders( Entity_Type => User_Entity_Type );

	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------

	type Authentication_Manager_Type is new KOW_Sec.Authentication_Manager_Interface with null record;

	-- This is where the magic happens!
	--
	-- The Authentication_Manager type is the type that should be extended
	-- when a new authentication method is implemented.
	--
	-- It's a controlled type only for the pleasure of the type implementor.


	function Do_Login(
				Manager	: in Authentication_Manager_Type;
				Username: in String;
				Password: in String
			) return User_Identity_Type;
	-- Login the user, returning a object representing it.
	-- This object might be a direct instance of User or a subclass.
	-- It's this way so the authentication method might have
	-- a user with extended properties.


	function Has_User(
				Manager		: Authentication_Manager_Type;
				User_Identity	: User_Identity_Type
			) return Boolean;
	-- check if the user is registered into this manager

	------------------------------
	-- User Creation Procedures --
	------------------------------

	function New_User(
				Username	: in String;
				Password	: in String
			) return User_Identity_Type;
	-- create a new user, saving it and then returning it's identity



end KOW_Sec_Entities;
