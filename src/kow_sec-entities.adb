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
with KOW_Ent.Data_Storages;
with KOW_Ent.Properties;
with KOW_Ent.Queries;
with KOW_Ent.Queries.Logic_Relations;
with KOW_Lib.String_Util;

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

		return KOW_Sec.To_Context( Ada.Tags.Expanded_Name(  Entity'Tag ) & "::" & KOW_Ent.To_String( KOW_Ent.Get_Value( KOW_Ent.Get_ID( Entity ) ) ) );
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

		Property.Value := KOW_Sec.To_Identity( Value.String_Value );
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
				Data_Storage	: in out KOW_Ent.Data_Storage_Interface'Class
			) is
	begin
		KOW_Ent.Create_Index(
					Data_Storage	=> Data_Storage,
					Entity_Tag	=> User_Entity_Type'Tag,
					Property_Names	=> ( 1 => Names.Username ),
					Is_Unique	=> True
				);

		KOW_Ent.Create_Index(
					Data_Storage	=> Data_Storage,
					Entity_Tag	=> User_Entity_Type'Tag,
					Property_Names	=> ( 1 => Names.Username, 2 => Names.Password ),
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
		return Get_User( Entity.User_Identity.Value );
	end To_User_Data;


	procedure Get_User_Entity(
				Entity	: in out User_Entity_Type;
				Username: in     String
			) is
		-- get the user entity by it's username
	begin
		null;
		--Load_Unique( Entity, Names.Username, Username );
	end Get_User_Entity;

	procedure Get_User_Entity(
				Entity		: in out User_Entity_Type;
				User_Identity	: in     KOW_Sec.User_Identity_Type
			) is
	-- get the user entity by it's user identity
	begin
		null;
		--Load_Unique( Entity, Names.Username, Username );
	end Get_User_Entity;



	---------------------------------
	-- Authentication Manager Type --
	---------------------------------


	function Get_Name( Manager : in Authentication_Manager_Type ) return String is
	begin
		return "ENTITY";
	end Get_Name;


	function Do_Login(
				Manager	: in Authentication_Manager_Type;
				Username: in String;
				Password: in String
			) return User_Identity_Type is

		use KOW_Ent.Queries;
		Template	: aliased User_Entity_Type;
	begin
		KOW_Lib.String_Util.Copy( From => Username, TO => Template.Username.String_Value );
		Extra_Properties.Set_Password( Template.Password, Password );

		declare
			Q : Query_Type;
			Username_Operation, Password_Operation : Logic_relations.Stored_Vs_Value_Operation;
			Username_Value : aliased Value_Type := Get_Value( Template.Username );
			Password_Value : aliased Value_Type := Get_Value( Template.Password );
		begin

			Username_Operation := (
							Entity_Tag	=> User_Entity_Type'Tag,
							Property_name	=> Names.Username,
							Value		=> Username_Value'Access,
							Relation	=> Relation_Equal_To,
							Operator	=> Operator_And
						);

			Password_Operation := (
							Entity_Tag	=> User_Entity_Type'Tag,
							Property_name	=> Names.Password,
							Value		=> Password_Value'Access,
							Relation	=> Relation_Equal_To,
							Operator	=> Operator_And
						);

			Append(
					Logic_Criteria	=> Q.Logic_Criteria,
					Operation	=> Username_Operation
				);

			Append(
					Logic_Crieteria	=> Q.Logic_Criteria,
					Operation	=> Password_Operation
				);

			declare
				use KOW_Ent.Data_Storages;
				Loader : Entity_Loader_Interface'Class := New_Loader( Data_Storage_Type'Class( Get_Data_Storage( User_Entity_Type'Tag ).all ), Q );
				Entity : User_Entity_Type;
			begin
				-- run the query
				Execute( Loader );

				-- fetch the results (if any)
				Fetch( Loader );
				if not Has_Element( Loader ) then
					raise KOW_Sec.INVALID_CREDENTIALS with "Login for the user """ & Username & """ failed!";
				end if;
				Load( Loader, Entity );


				-- check if it's the only result
				Fetch( Loader );
				if Has_Element( Loader ) then
					raise KOW_Sec.INVALID_CREDENTIALS with "Login with multiple results. This has got to be a bug.";
				end if;

				return Entity.User_Identity.Value;
			end;
		end;
	end Do_Login;

	function Has_User(
				Manager		: Authentication_Manager_Type;
				User_Identity	: User_Identity_Type
			) return Boolean is
		-- check if the user is registered into this manager
		use KOW_Ent;
		use KOW_Ent.Queries;

		Q : Query_Type;
		Identity_Value : aliased Value_Type( APQ_String, User_Identity'Length );
		Identity_Operation: Logic_relations.Stored_Vs_Value_Operation;
	begin
		Q.Entity_Type := User_Entity_Type'Tag;
		Identiy_Value.String_Value := To_String( User_Identity );

		Identity_Operation := (
						Entity_Tag	=> User_Entity_Type'Tag,
						Property_name	=> Names.User_Identity,
						Value		=> Identity_Value'Access,
						Relation	=> Relation_Equal_To,
						Operator	=> Operator_And
					);
		Append(
				Logic_Criteria	=> Q.Logic_Criteria,
				Operation	=> Identity_Operation
			);

		declare
			use KOW_Ent.Data_Storages;
			Loader : Entity_Loader_Interface'Class := New_Loader( Data_Storage_Type'Class( Get_Data_Storage( User_Entity_Type'Tag ).all ), Q );
		begin
			Execute( Loader );
			Fetch( Loader );
			return Has_Element( Loader );
			-- notice that false positives aren't that critical in this code
		end;
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
		use KOW_Lib.String_Util;
		Entity	: User_Entity_Type;
		Data	: KOW_Sec.User_Data_Type;
	begin
		Entity.User_Identity.Value := KOW_Sec.New_User_Identity;
		Copy( From => Username, To => Entity.Username.String_Value );
		Copy( From => Password, To => Entity.Password.String_Value );

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
		KOW_Lib.String_Util.Copy(From => New_Password, To => Entity.Password.String_Value );
		Store( Entity );
	end Change_Password;

end KOW_Sec.Entities;
