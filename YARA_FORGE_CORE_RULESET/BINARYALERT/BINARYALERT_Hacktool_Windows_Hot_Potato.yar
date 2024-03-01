rule BINARYALERT_Hacktool_Windows_Hot_Potato
{
	meta:
		description = "No description has been set in the source file - BinaryAlert"
		author = "@mimeframe"
		id = "dee13640-b4a9-5a39-af01-338c0197c995"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/foxglovesec/Potato"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_hot_potato.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "1ccee61660b3478294a5a4e1ca2b16c91156f6c877d0f83848cccd18a3f753f7"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "Parsing initial NTLM auth..." wide ascii
		$a2 = "Got PROPFIND for /test..." wide ascii
		$a3 = "Starting NBNS spoofer..." wide ascii
		$a4 = "Exhausting UDP source ports so DNS lookups will fail..." wide ascii
		$a5 = "Usage: potato.exe -ip" wide ascii

	condition:
		any of ($a*)
}
