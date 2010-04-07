

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
with KOW_Ent;			use KOW_Ent;
with KOW_Ent.Properties;

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
--
--	As of 2009-09-10 we stoped using ID generators in this package.
--
--	The reasons for this are:
--		1. the hash sometimes is greater than apq_bigserial'last
--		2. if the string is long, it's likelly you'll have the same hash for them...
--	Also, unicity can be (and should be) checked by your database backend.
--
--	function Generate_User_Id( User : in KOW_Ent.Entity_Type'Class ) return KOW_Ent.Id_Type is
--		ID : KOW_Ent.Id_Type;
--	begin
--		ID.My_Tag := User'Tag;
--		ID.Value := Calculate_Hashed_Id( KOW_Sec.Identity( User_Entity_Type( User ).User ) );
--		return ID;
--	end Generate_User_Id;
--
--
--	function Generate_Group_Id( Group : in KOW_Ent.Entity_Type'Class ) return KOW_Ent.Id_Type is
--		ID : KOW_Ent.Id_Type;
--	begin
--		ID.My_Tag := Group'Tag;
--		ID.Value := Calculate_Hashed_Id( To_String( Group ) );
--		return ID;
--	end Generate_Group_Id;



	overriding
	function To_Access( User : in User_Type ) return KOW_Sec.User_Access is
	begin
		return new User_Type'( User );
	end To_Access;


	----------------------
	-- USER ENTITY TYPE --
	----------------------


	overriding
	function To_String( Entity : in User_Entity_Type ) return String is
		-- return the user identity
	begin
		return Identity( Entity.User );
	end To_String;


	overriding
	function Describe( Entity : in User_Entity_Type ) return String is
		-- return the full name of the user
	begin
		return Full_name( Entity.User );
	end Describe;


	overriding
	function Image_URL( Entity : in User_Entity_Type ) return String is
		-- get the gravatar for the given user
	begin
		return Gravatar_URL( Entity.User );
	end Image_URL;


	
	function To_User( Entity : in User_Entity_Type ) return User_Type'Class is
		-- convert the entity to an KOW_sec.user type
		User : User_Type := Entity.User;
	begin
		User.ID		:= Entity.ID;
		return User;
	end To_User;


	function To_User_Entity( User : in User_Type ) return User_Entity_Type'Class is
		-- convert the user type to an user entity type
		-- assumes the user is already in the database.
		Entity : User_Entity_Type;
	begin
		Entity.User := User;
		Entity.ID := User.ID;
		-- Entity.Id := Generate_User_ID( Entity );
		return Entity;
	end To_User_Entity;



	------------------
	-- Group Entity --
	------------------
	
	overriding
	function To_String( Entity : in Group_Entity_Type ) return String is
		-- return the group name
	begin
		return To_String( Entity.User_Identity );
	end To_String;


	overriding
	function Describe( Entity : in Group_Entity_Type ) return String is
		-- return the group name...
	begin
		return To_String( Entity.Group );
	end Describe;

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


	function Get_User( Manager : in Authentication_Manager; Username : in String ) return User'Class is
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
		return To_User( Get_First( Q => Q, Unique => True ) );
	exception
		when NO_ENTITY =>
			raise KOW_Sec.UNKNOWN_USER with Username;
	end Get_User;


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
				Column		=> "user_identity",
				Value		=> KOW_Sec.Identity( User_Object )
			);
		Entity_Vectors.Iterate(
				Get_All( Q ),
				Iterator'Access
			);
		return The_Groups;
	end Get_Groups;




	------------------------------
	-- User Creation Procedures --
	------------------------------

	procedure New_User(
				Username	: in String;
				Password	: in String
				) is
		-- create a new user and store it in the database backend
		The_User : User_Entity_Type;
	begin
		The_User.User.Username := To_Unbounded_String( Username );
		The_User.Password := To_Unbounded_String( Password );

		Store( The_User );
	end New_User;
		

	procedure Add_Group(
				User_Identity	: in String;
				Group		: in String
			) is
		-- add the given user to the given group
		The_Group : Group_Entity_Type;
	begin
		The_Group.User_Identity := To_Unbounded_String( User_Identity );
		The_Group.Group := To_Unbounded_String( Group );


		Store( The_Group );
	end Add_Group;



	------------------------------------------------
	-- Getter and Setter for the User Entity Type --
	------------------------------------------------


	-- factory ::
	function User_Entity_Factory return Entity_Type'Class is
		Entity: User_Entity_Type;
	begin
		return Entity;
	end User_Entity_Factory;

	-- 
	-- username
	--
	procedure Set_U_Username( Entity : in out Entity_Type'Class; Username : in Unbounded_String ) is
	begin
		Set_Username(
				User_Entity_Type( Entity ).User,
				To_String( Username )
			);
	end Set_U_Username;

	function Get_U_Username( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return To_Unbounded_String(
				Get_Username( User_Entity_Type( Entity ).User )
			);
	end Get_U_Username;
	
	
	--
	-- first name
	--
	procedure Set_U_First_Name( Entity : in out Entity_Type'Class; First_Name : in Unbounded_String ) is
	begin
		Set_First_Name(
				User_Entity_Type( Entity ).User,
				To_String( First_Name )
			);
	end Set_U_First_Name;

	function Get_U_First_Name( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return To_Unbounded_String(
					Get_First_Name(
						User_Entity_Type( Entity ).User
					)
				);
	end Get_U_First_Name;
	
	--
	-- last name
	--
	procedure Set_U_Last_Name( Entity : in out Entity_Type'Class; Last_Name : in Unbounded_String ) is
	begin
		Set_Last_Name(
				User_Entity_Type( Entity ).User,
				To_String( Last_Name )
			);
	end Set_U_Last_Name;

	function Get_U_Last_Name( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return TO_Unbounded_String(
				Get_Last_Name(
						User_Entity_Type( Entity ).User
					)
				);
	end Get_U_Last_Name;


	--
	-- email 
	--
	procedure Set_U_Email( Entity : in out Entity_Type'Class; Email : in Unbounded_String ) is
	begin
		Set_Email(
				User_Entity_Type( Entity ).User,
				To_String( Email )
			);
	end Set_U_Email;

	function Get_U_Email( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return TO_Unbounded_String(
				Get_Email(
						User_Entity_Type( Entity ).User
					)
				);
	end Get_U_Email;



	--
	-- Password
	--
	procedure Set_U_Password( Entity : in out Entity_Type'Class; Password : in Unbounded_String ) is
	begin
		User_Entity_Type( Entity ).Password := Password;
	end Set_U_Password;

	function Get_U_Password( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return User_Entity_Type( Entity ).Password;
	end Get_U_Password;

	-------------------------------------------------
	-- Getter and Setter for the Group Entity Type --
	-------------------------------------------------


	-- factory ::
	function Group_Entity_Factory return Entity_Type'Class is
		Entity : Group_Entity_Type;
	begin
		return Entity;
	end Group_Entity_Factory;

	--
	-- Group
	--
	procedure Set_G_Group( Entity : in out Entity_Type'Class; Group : in Unbounded_String ) is
	begin
		Group_Entity_Type( Entity ).Group := KOW_Sec.Authorization_Group( Group );
	end Set_G_Group;

	function Get_G_Group( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return Unbounded_String( Group_Entity_Type( Entity ).Group );
	end Get_G_Group;


	--
	-- User
	--
	procedure Set_G_User_Identity( Entity : in out Entity_Type'Class; User_Identity : in Unbounded_String ) is
	begin
		Group_Entity_Type( Entity ).User_Identity := User_Identity;
	end Set_G_User_Identity;

	function Get_G_User_Identity( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return Group_Entity_Type( Entity ).User_Identity;
	end Get_G_User_Identity;



begin
	---------------------------
	-- register the entities --
	---------------------------

	--
	-- User Entity
	--
	KOW_Ent.Entity_Registry.Register(
			Entity_Tag	=> User_Entity_Type'Tag,
			Table_Name	=> "kow_users",
			Id_Generator	=> null,
			Factory		=> User_Entity_Factory'Access
		);
	
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> User_Entity_Type'Tag,
			Property	=> KOW_Ent.Properties.New_UString_Property(
						Column_Name	=> "username",
						Getter		=> Get_U_Username'Access,
						Setter		=> Set_U_Username'Access,
						Immutable	=> True
					),
			Is_Unique	=> True
		);
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> User_Entity_Type'Tag,
			Property	=> KOW_Ent.Properties.New_UString_Property(
						Column_Name	=> "first_name",
						Getter		=> Get_U_First_Name'Access,
						Setter		=> Set_U_First_Name'Access
					)
		);
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> User_Entity_Type'Tag,
			Property	=> KOW_Ent.Properties.New_UString_Property(
						Column_Name	=> "last_name",
						Getter		=> Get_U_Last_Name'Access,
						Setter		=> Set_U_Last_Name'Access
					)
		);
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> User_Entity_Type'Tag,
			Property	=> KOW_Ent.Properties.New_UString_Property(
						Column_Name	=> "email",
						Getter		=> Get_U_Email'Access,
						Setter		=> Set_U_Email'Access
					)
		);
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> User_Entity_Type'Tag,
			Property	=> KOW_Ent.Properties.New_Password_Property(
						Column_Name	=> "password",
						Getter		=> Get_U_Password'Access,
						Setter		=> Set_U_Password'Access
					)
		);

	-- group entity
	KOW_Ent.Entity_Registry.Register(
			Entity_Tag	=> Group_Entity_Type'Tag,
			Table_Name	=> "kow_groups",
			Id_Generator	=> null,
			Factory		=> Group_Entity_Factory'Access
		);
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> Group_Entity_Type'Tag,
			Property	=> KOW_Ent.Properties.New_UString_Property(
						Column_Name	=> "user_identity",
						Getter		=> Get_G_User_Identity'Access,
						Setter		=> Set_G_User_Identity'Access,
						Immutable	=> True
					)
		);
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> Group_Entity_Type'Tag,
			Property	=> KOW_Ent.Properties.New_UString_Property(
						Column_Name	=> "group_name",
						Getter		=> Get_G_Group'Access,
						Setter		=> Set_G_Group'Access,
						Immutable	=> True
					)
		);



end KOW_Sec.Authentication.Entities;
