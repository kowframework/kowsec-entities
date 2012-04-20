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
with KOW_Ent.Id_Query_Builders;	use KOW_Ent.Id_Query_Builders;
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


	---------------------------------
	-- User Identity Property Type --
	---------------------------------


	overriding
	function Get_Type( Property : User_Identity_Property_Type ) return KOW_Ent.Type_Of_Data_Type is
		-- always returns APQ_String
	begin
		return KOW_Ent.APQ_String;
	end Get_Type;

	overriding
	function Get_Value(
				Property	: in User_Identity_Property_Type;
				For_Store	: in Boolean
			) return KOW_Ent.Value_Type is
		-- read the value
		Str_Val : constant String := KOW_Sec.To_String( Property.Value );
		Val	: KOW_Ent.Value_Type( Type_Of => KOW_Ent.APQ_String, String_Length => Str_Val'Length );
	begin
		Val.String_Value := Str_Val;
		return Val;
	end Get_Value;


	overriding
	procedure Set_Value(
				Property	: in out User_Identity_Property_Type;
				Value		: in     KOW_Ent.Value_Type
			) is
		-- set the value
		use KOW_Ent;
	begin
		pragma Assert( Value.Type_Of = APQ_String, "Setting user identity from a non-string type" );

		Property.Value := KOW_Sec.To_String( Value.String_Value );
	end Set_Value;


	overriding
	function Is_Id( Property : in User_Identity_Property_Type ) return Boolean is
		-- returns property.is_id_property
	begin
		return Property.Is_Id_Property;
	end Is_Id;

	----------------------
	-- USER ENTITY TYPE --
	----------------------

	overriding
	procedure Post_Install(
				Entity		: in out User_Entity_Type;
				Data_Storage	: in out KOW_Ent.Data_Storage_Type'Class
			) is
	begin
		KOW_Ent.Create_Index(
					Data_Storage	=> Data_Storage,
					Entity_Tag	=> User_Entity_Type'Tag,
					Property_Names	=> ( 1 => Names.Login ),
					Is_Unique	=> True
				);

		KOW_Ent.Create_Index(
					Data_Storage	=> Data_Storage,
					Entity_Tag	=> User_Entity_Type'Tag,
					Property_Names	=> ( 1 => Names.Login, 2 => Names.Password ),
					Is_Unique	=> True
				);

		KOW_Ent.Create_Index(
					Data_Storage	=> Data_Storage,
					Entity_Tag	=> User_Entity_Type'Tag,
					Property_Names	=> ( 1 => Names.User_Identity ),
					Is_Unique	=> True
				);
	end Post_Install;


	function To_User_Data( Entity : in User_Entity_Type ) return User_Data_Type is
		-- convert the entity to an KOW_sec.user type
	begin
		return Get_User( Entity.User_Identity );
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


	function Get_User_Entity( Username: in String ) return User_Entity_Type is
		-- get the user entity by it's username
		use User_Query_Builders;
		Q : Entity_Query_Type;
	begin
		Append(
				Q		=> Q,
				Column		=> "username",
				Value		=> Username,
				Appender	=> Appender_AND,
				Operator	=> Operator_Equal_To
			);
		return Get_First( Q => Q, Unique => True );
	exception
		when NO_ENTITY =>
			raise KOW_Sec.UNKNOWN_USER with '"' & Username & '"';
	end Get_User_Entity;



	function Get_User_Entity( User_Identity : in KOW_Sec.User_Identity_Type ) return User_Entity_Type is
		-- get the user entity by it's user identity
		use User_Query_Builders;
		Q : Entity_Query_Type;
	begin
		Append(
				Q		=> Q,
				Column		=> "user_identity",
				Value		=> String( User_Identity ),
				Appender	=> Appender_And,
				Operator	=> Operator_Equal_To
			);

		return Get_First( Q => Q, Unique => True );
	end Get_User_Entity;


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

		Q : Entity_Query_Type;
		E : User_Entity_Type;
	begin
		Append(
				Q		=> Q,
				Column		=> "username",
				Value		=> Username,
				Appender	=> Appender_AND,
				Operator	=> Operator_Equal_To
			);

		Append_Password(
				Q		=> Q,
				Column		=> "password",
				Value		=> Password,
				Appender	=> Appender_AND,
				Operator	=> Operator_Equal_To
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

		Q : Entity_Query_Type;
		U : User_Entity_Type;
	begin
		Append(
				Q		=> Q,
				Column		=> "user_identity",
				Value		=> String( User_Identity ),
				Appender	=> Appender_AND,
				Operator	=> Operator_Equal_To
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

end KOW_Sec.Entities;
