

--------------
-- Ada 2005 --
--------------
with Ada.Strings.Hash;

---------
-- APQ --
---------
with APQ;

-------------------
-- KOW Framework --
-------------------


package body KOW_Sec.Authentication.Entities is


	----------------------
	-- Auxiliar Methods --
	----------------------

	function Calculate_Hashed_ID( Str_ID : in String ) return APQ.APQ_Bigserial is
	begin
		return APQ.APQ_Bigserial( Ada.Strings.Hash( Str_Id ) );
	end Calculate_Hashed_ID;


	-------------------
	-- ID Generators --
	-------------------
	function Generate_User_Id( User : in KOW_Ent.Entity_Type'Class ) return KOW_Ent.Id_Type is
		ID : KOW_Ent.Id_Type;
	begin
		ID.My_Tag := User'Tag;
		ID.Value := Calculate_Hashed_Id( KOW_Sec.Identity( User_Entity_Type( User ).User ) );
		return ID;
	end Generate_User_Id;


	function Generate_Group_Id( Group : in KOW_Ent.Entity_Type'Class ) return KOW_Ent.Id_Type is
		ID : KOW_Ent.Id_Type;
	begin
		ID.My_Tag := Group'Tag;
		ID.Value := Calculate_Hashed_Id(
					To_String( Group_Entity_Type( Group ).User )  & "::" &
					To_String( Group_Entity_Type( Group ).Group )
				);
		return ID;
	end Generate_Group_Id;

	----------------------
	-- USER ENTITY TYPE --
	----------------------


	overriding
	function To_String( Entity : in User_Entity_Type ) return String is
		-- return the user identity
	begin
		return KOW_Sec.Identity( Entity.User );
	end To_String;

	
	function To_User( Entity : in User_Entity_Type ) return KOW_Sec.User is
		-- convert the entity to an KOW_sec.user type
	begin
		return Entity.User;
	end To_User;


	function To_User_Entity( User : in KOW_Sec.User ) return User_Entity_Type is
		-- convert the user type to an user entity type
		-- assumes the user is already in the database.
		Entity : User_Entity_Type;
	begin
		Entity.User := User;
		Entity.Id := Generate_User_ID( Entity );
		return Entity;
	end To_User_Entity;



	------------------
	-- Group Entity --
	------------------
	
	overriding
	function To_String( Entity : in Group_Entity_Type ) return String is
		-- return the group name
	begin
		return To_String( Entity.Group );
	end To_String;


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
		return To_User( Get_First( Q => Q, Unique => True ) );
	exception
		when NO_ENTITY =>
			raise KOW_Sec.INVALID_CREDENTIALS with "Login for the user """ & Username & """ failed!";
	end Do_Login;


	function Get_Groups(	Manager:	in Authentication_Manager;
				User_Object:	in User'Class )
				return Authorization_Groups is
		-- get the groups for this user... entity group_entity
		use Group_Query_Builders;

		The_Groups : KOW_Sec.Authorization_Groups;
		procedure Iterator( C : in Entity_Vectors.Cursor ) is
		begin
			KOW_Sec.Authorization_Group_Vectors.Append(
						The_Groups,
						Entity_Vectors.Element( C ).Group
					);
		end Iterator;

		Q : Query_Type;
	begin
		Append(
				Q		=> Q,
				Column		=> "user",
				Value		=> KOW_Sec.Identity( User_Object )
			);
		Entity_Vectors.Iterate(
				Get_All( Q ),
				Iterator'Access
			);
		return The_Groups;
	end Get_Groups;

end KOW_Sec.Authentication.Entities;
