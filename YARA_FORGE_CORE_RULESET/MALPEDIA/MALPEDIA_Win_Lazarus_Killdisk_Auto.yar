rule MALPEDIA_Win_Lazarus_Killdisk_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "37962373-db6b-5a82-a667-796eaa294f65"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lazarus_killdisk"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.lazarus_killdisk_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "f14584aa2cdb4f56b5df407c3c19c0436c1677938983b3e7a6f77f9ce3d89a22"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8b530c 8b4308 33c9 8d4402ff 0fa4c109 }
		$sequence_1 = { e8???????? 83c40c 57 8d4c242c }
		$sequence_2 = { 8bf0 83feff 740e 8bce e8???????? 56 }
		$sequence_3 = { 6a00 6800000002 ffd3 8bf0 83feff 7409 6a00 }
		$sequence_4 = { 7438 8d55f0 52 68???????? }
		$sequence_5 = { 89842430020000 53 56 57 e8???????? 8b1d???????? 33ff }
		$sequence_6 = { 68???????? 57 ff15???????? 8b45a2 8b4da6 8b55ae }
		$sequence_7 = { 8d95c0fdffff c1e009 52 50 57 }
		$sequence_8 = { 40 83c610 8985e4fdffff 83f804 }
		$sequence_9 = { 8d5de8 8955ec 894df4 8945f0 e8???????? 807db600 }

	condition:
		7 of them and filesize <209920
}
