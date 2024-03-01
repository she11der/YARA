rule SIGNATURE_BASE_Equationdrug_Kernelrootkit
{
	meta:
		description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "92491e30-4041-5c8b-8e4e-7bc2b1d3234b"
		date = "2015-03-11"
		modified = "2023-01-06"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L472-L492"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"
		logic_hash = "4b41af8656ada1b4db7ec11f65aeb2d335f424d8557cfa74a064b40c65627012"
		score = 75
		quality = 60
		tags = ""

	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "Parmsndsrv.dbg" fullword ascii
		$s2 = "\\Registry\\User\\CurrentUser\\" wide
		$s3 = "msndsrv.sys" fullword wide
		$s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" wide
		$s6 = "\\Device\\%ws_%ws" wide
		$s7 = "\\DosDevices\\%ws" wide
		$s9 = "\\Device\\%ws" wide

	condition:
		all of them
}
