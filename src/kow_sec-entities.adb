------------------------------------------------------------------------------
--                                                                          --
--                       KOW Framework :: Security                          --
--                                                                          --
--                              KOW Framework                               --
--                                                                          --
--                                 B o d y                                  --
--                                                                          --
--               Copyright (C) 2007-2011, KOW Framework Project             --
--                                                                          --
--                                                                          --
-- KOWSec is free software; you can redistribute it  and/or modify it under --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 2,  or (at your option) any later ver- --
-- sion. KOWSec is distributed in the hope that it will be useful, but WITH---
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License --
-- for  more details.  You should have  received  a copy of the GNU General --
-- Public License distributed with KOWSec; see file COPYING.  If not, write --
-- to  the Free Software Foundation,  59 Temple Place - Suite 330,  Boston, --
-- MA 02111-1307, USA.                                                      --
--                                                                          --
-- As a special exception,  if other files  instantiate  generics from this --
-- unit, or you link  this unit with other files  to produce an executable, --
-- this  unit  does not  by itself cause  the resulting  executable  to  be --
-- covered  by the  GNU  General  Public  License.  This exception does not --
-- however invalidate  any other reasons why  the executable file  might be --
-- covered by the  GNU Public License.                                      --
--                                                                          --
------------------------------------------------------------------------------

--------------
-- Ada 2005 --
--------------
with Ada.Exceptions;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Hash;
with Ada.Tags;

---------
-- APQ --
---------
with APQ;

-------------------
-- KOW Framework --
-------------------
with KOW_Ent;			use KOW_Ent;
with KOW_Ent.Properties;

package body KOW_Sec.Entities is


	----------------------
	-- Context Handling --
	----------------------
	
	function To_Context(
			Entity_Tag	: in Ada.Tags.Tag;
			Id		: in Natural
		) return KOW_Sec.Context_Type is
		-- convert a given tagged type + id into a context
	begin
		return KOW_Sec.To_Context( Ada.Tags.Expanded_Name( Entity_Tag ) & "::" & Ada.Strings.Fixed.Trim( Natural'Image( Id ), Ada.Strings.Both ) );
	end To_Context;

	function To_Context( Entity : in KOW_Ent.Entity_Type'Class ) return KOW_Sec.Context_Type is
		-- conver a given entity into a context
	begin
		if KOW_Ent.Is_new( Entity ) then
			raise PROGRAM_ERROR with "can't convert a new entity into a context... call KOW_Ent.Store first";
		end if;

		return KOW_Sec.To_Context( Ada.Tags.Expanded_Name(  Entity'Tag ) & "::" & KOW_Ent.To_String( Entity.Id ) );
	end To_Context;

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



	----------------------
	-- USER ENTITY TYPE --
	----------------------


	overriding
	function To_String( Entity : in User_Entity_Type ) return String is
		-- return the user identity
	begin
		return String( Entity.User_Identity );
	end To_String;


	overriding
	function Describe( Entity : in User_Entity_Type ) return String is
		-- return the full name of the user
	begin
		return Full_name( Get_user( Entity.User_Identity ) );
	end Describe;


	overriding
	function Image_URL( Entity : in User_Entity_Type ) return String is
		-- get the gravatar for the given user
	begin
		return Gravatar_URL( Get_User( Entity.User_Identity ) );
	end Image_URL;


	
	function To_User_Data( Entity : in User_Entity_Type ) return User_Data_Type is
		-- convert the entity to an KOW_sec.user type
	begin
		return Get_user( Entity.User_Identity );
	end To_User_Data;


	function To_User_Entity( User : in User_Data_Type ) return User_Entity_Type is
		-- convert the user type to an user entity type
		-- assumes the user is already in the database.
		Entity : User_Entity_Type;
	begin
		Entity.User_Identity := User.Identity;

		-- TODO :: try to catch the username from the database backend...
		-- Entity.Id := Generate_User_ID( Entity );
		return Entity;
	end To_User_Entity;


	function Get_user_Entity( Username: in String ) return User_Entity_Type is
		-- get the user entity by it's username
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
		return Get_First( Q => Q, Unique => True );
	exception
		when NO_ENTITY =>
			raise KOW_Sec.UNKNOWN_USER with '"' & Username & '"';
	end Get_user_Entity;



	-------------------------------
	-- AUTHENTICATION MANAGEMENT --
	-------------------------------


	function Get_Name( Manager : in Authentication_Manager_Type ) return String is
	begin
		return "ENTITY";
	end Get_Name;


	function Do_Login(
				Manager	: in Authentication_Manager_Type;
				Username: in String;
				Password: in String
			) return User_Identity_Type is
		use User_Query_Builders;

		Q : Query_Type;
		E : User_Entity_Type;
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
		E := Get_First( Q => Q, Unique => True );


		return E.User_Identity;
	exception
		when NO_ENTITY =>
			raise KOW_Sec.INVALID_CREDENTIALS with "Login for the user """ & Username & """ failed!";
		when e : others =>
			Ada.Exceptions.Reraise_Occurrence( e );
	end Do_Login;

	function Has_User(
				Manager		: Authentication_Manager_Type;
				User_Identity	: User_Identity_Type
			) return Boolean is
		-- check if the user is registered into this manager
		use User_Query_Builders;

		Q : Query_Type;
		U : User_Entity_Type;
	begin
		Append(
				Q		=> Q,
				Column		=> "user_identity",
				Value		=> String( User_Identity ),
				Appender	=> Appender_AND,
				Operator	=> Operator_Equals
			);

		U := Get_First( Q => Q, Unique => True );

		return True;
	exception
		when NO_ENTITY =>
			return false;
	end Has_User;



	------------------------------
	-- User Creation Procedures --
	------------------------------

	function New_User(
				Username	: in String;
				Password	: in String;
				Account_Status	: in KOW_Sec.Account_Status_Type := KOW_Sec.Account_Enabled
			) return User_Identity_Type is
		-- create a new user and store it in the database backend
		Entity	: User_Entity_Type;
		Data	: KOW_Sec.User_Data_Type;
	begin
		Entity.User_Identity	:= KOW_Sec.New_User_Identity;
		Entity.Username := To_Unbounded_String( Username );
		Entity.Password := To_Unbounded_String( Password );

		Store( Entity );
		-- if the username is duplicated, an exception will be raised right here :)
		-- so.... the user won't be saved at all


		Data.Identity := Entity.User_Identity;
		Data.Account_Status := Account_Status;
		KOW_Sec.Store_User( Data );

		return Entity.User_Identity;
	end New_User;
		


	procedure Change_Password(
				Username	: in String;
				New_Password	: in String
			) is
		-- change the user's password
		Entity : User_Entity_Type := Get_User_Entity( Username );
	begin
		Entity.Password := To_Unbounded_String( New_Password );
		Store( Entity );
	end Change_Password;


	---------------------------------
	-- USER IDENTITY PROPERTY TYPE --
	---------------------------------


	procedure Set_Property(	
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in out Entity_Type'Class;		-- the entity
				Q		: in out APQ.Root_Query_Type'Class;	-- the query from witch to fetch the result
				Connection	: in out APQ.Root_Connection_type'Class		-- the connection that belongs the query
			) is
		-- Set the property into the Entity.

		Column : String := To_String( Property.Column_Name );
		Index  : APQ.Column_Index_Type := APQ.Column_Index( Q, Column );
		Value  : String := APQ.Value( Q, Index );
	begin
		Property.Setter.all(
				Entity,
				To_Identity( Value )
			);
	exception
		when APQ.Null_Value =>
			Property.Setter.all(
				Entity,
				Property.Default_Value
			);
	end Set_Property;

	procedure Get_Property(
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in     Entity_Type'Class;		-- the entity
				Query		: in out APQ.Root_Query_Type'Class;	-- the query to witch append the value to insert
				Connection	: in out APQ.Root_Connection_type'Class		-- the connection that belongs the query
			) is
	begin
		APQ.Append_Quoted( Query, Connection, To_String( Property.Getter.All( Entity ) ) );
	end Get_Property;

	overriding
	procedure Set_Property(
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in out Entity_Type'Class;		-- the entity
				Value		: in     String				-- the String representation of this value
			) is
		-- Set the property from a String representation of the value
	begin
		Property.Setter.all( Entity, To_Identity( Value ) );
	end Set_Property;
	
	overriding
	function Get_Property(
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in     Entity_Type'Class		-- the entity
			) return String is
	begin
		return To_String( Property.Getter.all( Entity ) );
	end Get_Property;


	overriding
	procedure Append_Create_Table( Property : in User_Identity_Property_Type; Query : in out APQ.Root_Query_Type'Class ) is
	begin
		APQ.Append(
				Query,
				To_String( Property.Column_Name ) &
						" VARCHAR( 32 ) NOT NULL"
			);
	end Append_Create_Table;



	function New_User_Identity_Property(
				Column_Name	: in     String;
				Getter		: User_Identity_Getter_Callback;
				Setter		: User_Identity_Setter_Callback;
				Default_Value	: in     User_Identity_Type := Anonymous_User_Identity;
				Immutable	: in     Boolean := False
			) return Entity_Property_Ptr is
		-- used to assist the creation of User_Identity properties.
		UId : User_Identity_Property_Type;
	begin
		UId.Column_Name	:= To_Unbounded_String( Column_Name );
		UId.Getter		:= Getter;
		UId.Setter		:= Setter;
		UId.Default_Value	:= Default_Value;
		UId.Immutable		:= Immutable;
		return new User_Identity_Property_Type'( UId );
	end New_User_Identity_Property;





	------------------------------------------------
	-- Getter and Setter for the User Entity Type --
	------------------------------------------------


	-- factory ::
	function User_Entity_Factory return Entity_Type'Class is
--		Entity: User_Entity_Type;
	begin
		return User_Entity_Type'( others => <> );
	end User_Entity_Factory;


	--
	-- identity
	--
	procedure Set_U_Identity( Entity : in out Entity_Type'Class; Identity : in User_Identity_type ) is
	begin
		User_Entity_Type( Entity ).User_Identity := Identity;
	end Set_U_Identity;

	function Get_U_Identity( Entity : in Entity_Type'Class ) return User_Identity_Type is
	begin
		return User_Entity_Type( Entity ).User_Identity;
	end Get_U_Identity;
	



	-- 
	-- username
	--
	procedure Set_U_Username( Entity : in out Entity_Type'Class; Username : in Unbounded_String ) is
	begin
		User_Entity_Type( Entity ).Username := Username;
	end Set_U_Username;

	function Get_U_Username( Entity : in Entity_Type'Class ) return Unbounded_String is
	begin
		return User_Entity_Type( Entity ).Username;
	end Get_U_Username;
	
	

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
			Property	=> KOW_Ent.Properties.New_Password_Property(
						Column_Name	=> "password",
						Getter		=> Get_U_Password'Access,
						Setter		=> Set_U_Password'Access
					)
		);
	KOW_Ent.Entity_Registry.Add_Property(
			Entity_Tag	=> User_Entity_Type'Tag,
			Property	=> New_User_Identity_Property(
						Column_Name	=> "user_identity",
						Getter		=> Get_U_Identity'Access,
						Setter		=> Set_U_Identity'Access
					),
			Is_Unique	=> True
		);

end KOW_Sec.Entities;
