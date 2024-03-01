rule SIGNATURE_BASE_Cobaltstrike_Unmodifed_Beacon
{
	meta:
		description = "Detects unmodified CobaltStrike beacon DLL"
		author = "yara@s3c.za.net"
		id = "8eeb03f9-9698-5a46-b45b-224d5c3f3df7"
		date = "2019-08-16"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cobaltstrike_evasive.yar#L309-L320"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "10114a431fb70be8e18e67b22aa76bf2c0536f07d373f717c1dc51755e0847c9"
		score = 75
		quality = 85
		tags = ""

	strings:
		$loader_export = "ReflectiveLoader"
		$exportname = "beacon.dll"

	condition:
		all of them
}
