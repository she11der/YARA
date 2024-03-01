import "pe"

rule SIGNATURE_BASE_Securityxploded_Producer_String : FILE
{
	meta:
		description = "Detects hacktools by SecurityXploded"
		author = "Florian Roth (Nextron Systems)"
		id = "739c4ba1-5126-51cc-a2dd-cdac2737e29a"
		date = "2017-07-13"
		modified = "2023-12-05"
		reference = "http://securityxploded.com/browser-password-dump.php"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3819-L3833"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "101e0b8b8aeb8ed4314bc07139dcc2b40600fde82ff786d15a15c10692f9aa4a"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d57847db5458acabc87daee6f30173348ac5956eb25e6b845636e25f5a56ac59"

	strings:
		$x1 = "http://securityxploded.com" fullword ascii

	condition:
		( uint16(0)==0x5a4d and all of them )
}
