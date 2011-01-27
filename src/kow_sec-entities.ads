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


-------------------
-- KOW Framework --
-------------------
with KOW_Ent;				use KOW_Ent;
with KOW_Ent.Query_Builders;
with KOW_Sec;				use KOW_Sec;

with APQ;

package KOW_Sec.Entities is



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


	
	function To_User_Data( Entity : in User_Entity_Type ) return User_Data_Type;
	-- convert the entity to an KOW_sec.user type

	function To_User_Entity( User : in User_Data_Type ) return User_Entity_Type;
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



	---------------------------------
	-- USER IDENTITY PROPERTY TYPE --
	---------------------------------

	type User_Identity_Getter_Callback is access function( Entity : in KOW_Ent.Entity_Type'Class ) return User_Identity_Type;
	type User_Identity_Setter_Callback is access procedure( Entity : in out KOW_Ent.Entity_Type'Class; Value : in User_Identity_Type );

	type User_Identity_Property_Type is new KOW_Ent.Entity_Property_Type with record
		Getter		: User_Identity_Getter_Callback;
		Setter		: User_Identity_Setter_Callback;
		Default_Value	: User_Identity_Type;
	end record;


	overriding
	procedure Set_Property(	
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in out Entity_Type'Class;		-- the entity
				Q		: in out APQ.Root_Query_Type'Class;	-- the query from witch to fetch the result
				Connection	: in out APQ.Root_Connection_type'Class		-- the connection that belongs the query
			);
	-- Set the property into the Entity.

	overriding
	procedure Get_Property(
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in     Entity_Type'Class;		-- the entity
				Query		: in out APQ.Root_Query_Type'Class;	-- the query to witch append the value to insert
				Connection	: in out APQ.Root_Connection_type'Class		-- the connection that belongs the query
			);



	overriding
	procedure Set_Property(
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in out Entity_Type'Class;		-- the entity
				Value		: in     String				-- the String representation of this value
			);
	-- Set the property from a String representation of the value
	
	overriding
	function Get_Property(
				Property	: in     User_Identity_Property_Type;		-- the property worker
				Entity		: in     Entity_Type'Class		-- the entity
			) return String;


	overriding
	procedure Append_Create_Table( Property : in User_Identity_Property_Type; Query : in out APQ.Root_Query_Type'Class );


	function New_User_Identity_Property(
				Column_Name	: in     String;
				Getter		: User_Identity_Getter_Callback;
				Setter		: User_Identity_Setter_Callback;
				Default_Value	: in     User_Identity_Type := Anonymous_User_Identity;
				Immutable	: in     Boolean := False
			) return Entity_Property_Ptr;
	-- used to assist the creation of User_Identity properties.
	-- default_value represents the value to be set when the one retoner from database is NULL

end KOW_Sec.Entities;
