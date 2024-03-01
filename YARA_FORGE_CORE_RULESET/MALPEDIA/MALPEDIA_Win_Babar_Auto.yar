rule MALPEDIA_Win_Babar_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "907c27e3-2fb8-508f-9c67-d8826ced6045"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.babar"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.babar_auto.yar#L1-L166"
		license_url = "N/A"
		logic_hash = "8e0331df8b3130917de8e5e3d5d2fa36fbe1f95285a5ec05160d56f936d6e114"
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
		$sequence_0 = { 3bd6 0f86f9feffff 8b54243c 8b442438 }
		$sequence_1 = { 3bd6 0f8c7affffff 8bbc24d0000000 ddd9 }
		$sequence_2 = { 3bd5 7e47 8d0c9500000000 2bd9 }
		$sequence_3 = { 3bd5 0f8671ffffff 8144241890020000 ddd8 816c242880020000 83c710 81c680020000 }
		$sequence_4 = { 46 8d44af08 8d5708 8d4cb500 d942f8 }
		$sequence_5 = { 3bd6 0f82eefeffff 8b742458 03f5 }
		$sequence_6 = { 3bd6 721b 57 8bcb }
		$sequence_7 = { 3bd6 72d9 33f6 eb08 }
		$sequence_8 = { 8906 0f8496000000 50 ffd7 894604 8b0d???????? 894e08 }
		$sequence_9 = { 8d8407d8988069 c1c007 8bfa 03c6 33fe }
		$sequence_10 = { 803800 8b0d???????? 741d 803900 7506 8b0d???????? 8a11 }
		$sequence_11 = { 23d1 33d0 0354244c 8d94322108b449 c1ca0a 03d1 8bf1 }
		$sequence_12 = { 57 8d3c85a09e0110 8b07 03c3 8a4824 }
		$sequence_13 = { e8???????? 57 e8???????? 83c410 8d842480000000 50 ffd5 }
		$sequence_14 = { 0fb64e04 884804 8b5604 c1ea08 885005 0fb64e06 }
		$sequence_15 = { 8b4b04 55 8b2d???????? 68???????? }

	condition:
		7 of them and filesize <1294336
}
