--------------------------------------------------------------------------------
-- util functions
--------------------------------------------------------------------------------

local function divide_string( str, max )
   local result = {}

   local start = 1
   for i = 1, #str do
      if i % max == 0 then
         table.insert( result, str:sub( start, i ) )
         start = i + 1
      elseif i == #str then
         table.insert( result, str:sub( start, i ) )
      end
   end

   return result
end

local function number_to_bit( num, length )
   local bits = {}

   while num > 0 do
      local rest = math.floor( math.fmod( num, 2 ) )
      table.insert( bits, rest )
      num = ( num - rest ) / 2
   end

   while #bits < length do
      table.insert( bits, "0" )
   end

   return string.reverse( table.concat( bits ) )
end

--------------------------------------------------------------------------------

local basexx = {}

--------------------------------------------------------------------------------
-- base2(bitfield) decode and encode function
--------------------------------------------------------------------------------

local bitMap = { o = "0", i = "1", l = "1" }

function basexx.to_bit( str )
   return ( str:gsub( '.', function ( c )
               local byte = string.byte( c )
               local bits = {}
               for _ = 1,8 do
                  table.insert( bits, byte % 2 )
                  byte = math.floor( byte / 2 )
               end
               return table.concat( bits ):reverse()
            end ) )
end

--------------------------------------------------------------------------------
-- generic function to decode and encode base32/base64
--------------------------------------------------------------------------------

local function to_basexx( str, alphabet, bits, pad )
   local bitString = basexx.to_bit( str )

   local chunks = divide_string( bitString, bits )
   local result = {}
   for _,value in ipairs( chunks ) do
      if ( #value < bits ) then
         value = value .. string.rep( '0', bits - #value )
      end
      local pos = tonumber( value, 2 ) + 1
      table.insert( result, alphabet:sub( pos, pos ) )
   end

   table.insert( result, pad )
   return table.concat( result )
end

--------------------------------------------------------------------------------
-- rfc 3548: http://www.rfc-editor.org/rfc/rfc3548.txt
--------------------------------------------------------------------------------

local base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
local base32PadMap = { "", "======", "====", "===", "=" }

function basexx.from_base32( str, ignore )
   str = ignore_set( str, ignore )
   return from_basexx( string.upper( str ), base32Alphabet, 5 )
end

function basexx.to_base32( str )
   return to_basexx( str, base32Alphabet, 5, base32PadMap[ #str % 5 + 1 ] )
end

--------------------------------------------------------------------------------
-- base64 decode and encode function
--------------------------------------------------------------------------------

local base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"..
                       "abcdefghijklmnopqrstuvwxyz"..
                       "0123456789+/"
local base64PadMap = { "", "==", "=" }

function basexx.from_base64( str, ignore )
   str = ignore_set( str, ignore )
   return from_basexx( str, base64Alphabet, 6 )
end

function basexx.to_base64( str )
   return to_basexx( str, base64Alphabet, 6, base64PadMap[ #str % 3 + 1 ] )
end

--------------------------------------------------------------------------------
-- URL safe base64 decode and encode function
--------------------------------------------------------------------------------

local url64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"..
                      "abcdefghijklmnopqrstuvwxyz"..
                      "0123456789-_"

function basexx.from_url64( str, ignore )
   str = ignore_set( str, ignore )
   return from_basexx( str, url64Alphabet, 6 )
end

function basexx.to_url64( str )
   return to_basexx( str, url64Alphabet, 6, "" )
end

return basexx
