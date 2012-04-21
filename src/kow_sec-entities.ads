------------------------------------------------------------------------------
--                                                                          --
--                       KOW Framework :: Security                          --
--                                                                          --
--                              KOW Framework                               --
--                                                                          --
--                                 S p e c                                  --
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


------------------------------------------------------------------------------
-- Main package for KOW Sec Entities                                        --
--                                                                          --
-- This package implements an Authorization Manager using KOW_Ent as the    --
-- backend for login data                                                   --
------------------------------------------------------------------------------

--------------
-- Ada 2005 --
--------------
with Ada.Strings.Unbounded;		use Ada.Strings.Unbounded;
with Ada.Tags;


-------------------
-- KOW Framework --
-------------------
with KOW_Ent;				use KOW_Ent;
with KOW_Ent.DB.Data_Storages;
with KOW_Ent.Extra_Properties;
with KOW_Ent.Properties;
with KOW_Sec;				use KOW_Sec;

with APQ;

package KOW_Sec.Entities is


	----------------------
	-- Context Handling --
	----------------------
	
	function To_Context(
			Entity_Tag	: in Ada.Tags.Tag;
			Id		: in Natural
		) return KOW_Sec.Context_Type;
	-- convert a given tagged type + id into a context
	

	function To_Context( Entity : in KOW_Ent.Entity_Type'Class ) return KOW_Sec.Context_Type;
	-- conver a given entity into a context



	---------------------------------
	-- User Identity Property Type --
	---------------------------------

	type User_Identity_Property_Type(
					Name		: KOW_Ent.Property_Name_Type;
					Container	: KOW_Ent.Property_Container_Ptr;
					Is_Id_Property	: Boolean
				) is new KOW_Ent.Property_Type( Name, Container, false ) with record
		-- The user identity must always be set as the functions of the property type expects
		-- it to be a valid identity
		Value	: KOW_Sec.User_Identity_Type := KOW_Sec.Anonymous_User_Identity;
	end record;

	overriding
	function Get_Type( Property : User_Identity_Property_Type ) return KOW_Ent.Type_Of_Data_Type;
	-- always returns APQ_String

	overriding
	function Get_Value(
				Property	: in User_Identity_Property_Type;
				For_Store	: in Boolean
			) return KOW_Ent.Value_Type;
	-- read the value
	
	overriding
	procedure Set_Value(
				Property	: in out User_Identity_Property_Type;
				Value		: in     KOW_Ent.Value_Type
			);
	-- set the value


	overriding
	function Is_Id( Property : in User_Identity_Property_Type ) return Boolean;
	-- returns property.is_id_property


	----------------------
	-- User Entity Type --
	----------------------

	package Names is
		User_Identity	: constant KOW_Ent.Property_Name_Type := new String'( "user_identity" );
		Username	: constant KOW_Ent.Property_Name_Type := new String'( "username" );
		Password	: constant KOW_Ent.Property_Name_Type := new String'( "password" );
	end Names;

	type User_Entity_Type is new KOW_Ent.Entity_Type with record
		User_Identity	: User_Identity_Property_Type(
								Name		=> Names.User_Identity,
								Container	=> User_Entity_Type'Unrestricted_Access,
								Is_Id_Property	=> True
							);

		Username	: KOW_Ent.Properties.String_Property(
								Name		=> Names.Username,
								Container	=> User_Entity_Type'Unrestricted_Access,
								String_Length	=> 100,
								Allow_Null	=> False
							);
		-- the login can be the user email address; in which case proper email validation
		-- should be implemented.

		Password	: KOW_Ent.Extra_Properties.Password_Property_Type(
								Name		=> Names.Password,
								Container	=> User_Entity_Type'Unrestricted_Access
							);
	end record;



	overriding
	procedure Post_Install(
				Entity		: in out User_Entity_Type;
				Data_Storage	: in out KOW_Ent.Data_Storage_Interface'Class
			);
	
	
	function To_User_Data( Entity : in User_Entity_Type ) return User_Data_Type;
	-- convert the entity to an KOW_sec.user type

	procedure Get_User_Entity(
				Entity	: in out User_Entity_Type;
				Username: in     String
			);
	-- get the user entity by it's username

	procedure Get_User_Entity(
				Entity		: in out User_Entity_Type;
				User_Identity	: in     KOW_Sec.User_Identity_Type
			);
	-- get the user entity by it's user identity



	package User_Storages is new KOW_Ent.DB.Data_Storages(
								Entity_Type	=> User_Entity_Type,
								Entity_Alias	=> "kow_users"
							);

	---------------------------------
	-- Authentication Manager Type --
	---------------------------------

	type Authentication_Manager_Type is new KOW_Sec.Authentication_Manager_Interface with null record;

	-- This is where the magic happens!
	--
	-- The Authentication_Manager type is the type that should be extended
	-- when a new authentication method is implemented.
	--
	-- It's a controlled type only for the pleasure of the type implementor.


	function Get_Name( Manager : in Authentication_Manager_Type ) return String;
	-- return ENTITY

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
				Password	: in String;
				Account_Status	: in KOW_Sec.Account_Status_Type := KOW_Sec.Account_Enabled
			) return User_Identity_Type;
	-- create a new user, saving it and then returning it's identity


	procedure Change_Password(
				Username	: in String;
				New_Password	: in String
			);
	-- change the user's password

end KOW_Sec.Entities;
