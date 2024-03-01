rule MALPEDIA_Win_Electric_Powder_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6da8b24a-07fd-5fc6-a509-6cbc31d92594"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.electric_powder"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.electric_powder_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "38cd56e857c27f71ed9be956ee8235c5f49da7b5b360cadbe53a42a73ba8199e"
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
		$sequence_0 = { 3b4e08 0f8324010000 8b4604 c704c810000000 8b4608 83e801 8945fc }
		$sequence_1 = { 03c0 660f289800904300 660f2835???????? 660f59cf 660f58d1 660f70caee f20f59d7 }
		$sequence_2 = { 8d8d20fdffff c78530fdffff00000000 c78534fdffff0f000000 c68520fdffff00 e8???????? c745fc00000000 8d8d20fdffff }
		$sequence_3 = { 7202 8b39 8b4110 85c0 7449 48 83ceff }
		$sequence_4 = { 0f8389010000 8b5604 3bc8 0f8388010000 8b44fa04 8944ca04 }
		$sequence_5 = { c645fc20 51 8bd0 8d8d78fcffff e8???????? 83c404 68???????? }
		$sequence_6 = { 50 51 8d8d68faffff e8???????? 83bd7cfaffff08 8d8568faffff }
		$sequence_7 = { 7202 8b3f 83fa08 731a }
		$sequence_8 = { 83c404 89b518efffff 85f6 0f84be000000 8b8d40efffff 03c9 }
		$sequence_9 = { 83f8ff 773b 83f8ef 7736 8b4f04 83c010 50 }

	condition:
		7 of them and filesize <565248
}
