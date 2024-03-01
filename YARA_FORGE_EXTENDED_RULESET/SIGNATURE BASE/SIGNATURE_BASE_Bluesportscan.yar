import "pe"

rule SIGNATURE_BASE_Bluesportscan
{
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "4bcb8b7c-5e22-5496-9a29-66e85e3c3395"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L409-L420"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6292f5fc737511f91af5e35643fc9eef"
		logic_hash = "5cb4e4b87eaf166c85d23114f5abc10ef83b4a29968bf6fef4b3fce7ff2787fd"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"

	condition:
		all of them
}
