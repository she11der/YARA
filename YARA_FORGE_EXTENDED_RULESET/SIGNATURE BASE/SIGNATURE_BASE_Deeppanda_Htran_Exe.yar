rule SIGNATURE_BASE_Deeppanda_Htran_Exe
{
	meta:
		description = "Hack Deep Panda - htran-exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2a551e82-aff1-5a77-bc5e-d06e49dca8bc"
		date = "2015-02-08"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_deeppanda.yar#L51-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
		logic_hash = "9ac5ddc53d3d5292acb3dcf68e66bc3f6ab4b8e61a71597dd84454adc516f95d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s2 = "\\Release\\htran.pdb" ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s8 = "======================== htran V%s =======================" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s15 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii

	condition:
		1 of them
}
