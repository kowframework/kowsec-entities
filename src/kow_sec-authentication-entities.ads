


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

	function To_User_Entity( User : in KOW_Sec.User ) return User_Entity_Type;
	-- convert the user type to an user entity type
	-- assumes the user is already in the database.



	------------------
	-- Group Entity --
	------------------
	
	type Group_Entity_Type is new KOW_Ent.Entity_Type with private;
	-- represents an authorization group in the database
	-- note that it's not related to the Entity_Type class
	-- This is to be compatible with the main KOW_Sec's specification

	overriding
	function To_String( Entity : in Group_Entity_Type ) return String;
	-- return the group name

	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------

	type Authentication_Manager is new KOW_Sec.Authentication_Manager with private;
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
	-- get the groups for this user... entity group_entity





private
	type User_Entity_Type is new KOW_Ent.Entity_Type with record
		User : KOW_Sec.User;
		-- there is no really need to duplicate all the parameters in here
		-- instead, we have a nested user
	end record;
	package User_Query_Builders is new KOW_Ent.Query_Builders( Entity_Type => User_Entity_Type );
	
	type Group_Entity_Type is new KOW_Ent.Entity_Type with record
		Group : KOW_Sec.Authorization_Group;
		User  : Unbounded_String;
	end record;
	package Group_Query_Builders is new KOW_Ent.Query_Builders( Entity_Type => Group_Entity_Type );

	type Authentication_Manager is new KOW_Sec.Authentication_Manager with null record;

end KOW_Sec.Authentication.Entities;
