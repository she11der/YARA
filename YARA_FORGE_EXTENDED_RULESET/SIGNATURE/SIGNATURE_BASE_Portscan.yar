import "pe"

rule SIGNATURE_BASE_Portscan
{
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "967d6e3b-ae0d-5f93-a20d-742fc010608d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L364-L375"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
		logic_hash = "d93b54ffc7416b5354304daf156908f11d7e320a91bd936e397a15ede63caae3"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s5 = "0    :SCAN BEGUN ON PORT:"
		$s6 = "0    :PORTSCAN READY."

	condition:
		all of them
}
