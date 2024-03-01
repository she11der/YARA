rule SIGNATURE_BASE_MAL_Driver_Sensecorp_7F45
{
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - Sense5Ext.sys"
		author = "Florian Roth"
		id = "6c1f5ba4-fd14-5069-9d99-e3072b2dbbc2"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_mal_drivers.yar#L225-L242"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7f4555a940ce1156c9bcea9a2a0b801f9a5e44ec9400b61b14a7b1a6404ffdf6"
		logic_hash = "dbef723d7e44da110675402fc13708c5b077eeb6a66c1772885f5879d795ec4e"
		score = 70
		quality = 85
		tags = ""

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00530065006e0073006500350020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00530065006e00730065003500200043004f00520050 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0032002e0036002e0030002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e0036002e0030002e0030 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000320032 }

	condition:
		all of them
}
