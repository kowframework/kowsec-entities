


--------------
-- Ada 2005 --
--------------
with Ada.Strings.Unbounded;		use Ada.Strings.Unbounded;


---------------
-- Ada Works --
---------------
with KOW_Ent;
with KOW_Ent.Query_Builders;
with KOW_Sec;


package KOW_Sec.Authentication.Entities is



	---------------
	-- USER TYPE --
	---------------

	type User_Type is new KOW_Sec.User with record
		ID		: KOW_Ent.ID_Type;
	end record;


	overriding
	function To_Access( User : in User_Type ) return KOW_Sec.User_Access;


	----------------------
	-- USER ENTITY TYPE --
	----------------------

	type User_Entity_Type is new KOW_Ent.Entity_Type with record
		-- This represents the user data in the data base
		-- The ID for this entity is the Hash code for the username
		--
		-- This is how we make sure each user name is unique.


		User : User_Type;
		-- there is no really need to duplicate all the parameters in here
		-- instead, we have a nested user

		Password : Unbounded_String;
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


	
	function To_User( Entity : in User_Entity_Type ) return User_Type'Class;
	-- convert the entity to an KOW_sec.user type

	function To_User_Entity( User : in User_Type ) return User_Entity_Type'Class;
	-- convert the user type to an user entity type
	-- assumes the user is already in the database.


	package User_Query_Builders is new KOW_Ent.Query_Builders( Entity_Type => User_Entity_Type );

	------------------
	-- Group Entity --
	------------------
	
	type Group_Entity_Type is new KOW_Ent.Entity_Type with record
		-- represents an authorization group in the database
		-- note that it's not related to the Entity_Type class
		-- This is to be compatible with the main KOW_Sec's specification
		Group		: KOW_Sec.Authorization_Group;
		User_Identity	: Unbounded_String;
	end record;


	overriding
	function To_String( Entity : in Group_Entity_Type ) return String;
	-- return the user identity for this group 

	overriding
	function Describe( Entity : in Group_Entity_Type ) return String;
	-- return the group name...
	

	--overriding
	--TODO :: function Image_URL( Entity : in Group_Entity_Type ) return String;
	-- get the gravatar URL for the related user

	package Group_Query_Builders is new KOW_Ent.Query_Builders( Entity_Type => Group_Entity_Type );

	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------

	type Authentication_Manager is new KOW_Sec.Authentication_Manager with null record;

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

	function Get_User( Manager : in Authentication_Manager; Username : in String ) return User'Class;


	function Get_Groups(	Manager:	in Authentication_Manager;
				User_Object:	in User'Class )
				return Authorization_Groups;
	-- get the groups for this user... entity group_entity





	------------------------------
	-- User Creation Procedures --
	------------------------------

	procedure New_User(
				Username	: in String;
				Password	: in String
				);
	-- create a new user and store it in the database backend
	

	procedure Add_Group(
				User_Identity	: in String;
				Group		: in String
			);
	-- add the given user to the given group


end KOW_Sec.Authentication.Entities;
