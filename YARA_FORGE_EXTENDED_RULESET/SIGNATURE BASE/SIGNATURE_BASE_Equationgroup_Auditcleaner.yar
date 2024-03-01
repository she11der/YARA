rule SIGNATURE_BASE_Equationgroup_Auditcleaner : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file Auditcleaner"
		author = "Florian Roth (Nextron Systems)"
		id = "39ed798a-221d-5a4b-8809-db01d5241418"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L84-L102"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "30a6ae9ce7d02c1d945d57eabf29f430ad4cdbc48dba5fe71654efc2c59fde08"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8c172a60fa9e50f0df493bf5baeb7cc311baef327431526c47114335e0097626"

	strings:
		$x1 = "> /var/log/audit/audit.log; rm -f ." ascii
		$x2 = "Pastables to run on target:" ascii
		$x3 = "cp /var/log/audit/audit.log .tmp" ascii
		$l1 = "Here is the first good cron session from" fullword ascii
		$l2 = "No need to clean LOGIN lines." fullword ascii

	condition:
		( filesize <300KB and 1 of them )
}
