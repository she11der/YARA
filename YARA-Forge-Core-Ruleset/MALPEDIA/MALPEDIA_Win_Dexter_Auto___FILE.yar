rule MALPEDIA_Win_Dexter_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5ebe4c09-da98-582c-8eed-df32a16fd066"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dexter"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dexter_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "88383a20a07c3308fad4494ea352148cf37f604e3e0c05d6e635ee453d38e768"
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
		$sequence_0 = { 8b5508 83c201 895508 8d45f4 }
		$sequence_1 = { c705????????00000000 a1???????? 0305???????? 8945fc 8b4d0c }
		$sequence_2 = { eb17 837df400 7511 6a01 e8???????? }
		$sequence_3 = { 50 e8???????? 83c410 8b4df8 51 6a00 8b15???????? }
		$sequence_4 = { 7507 b801000000 eb0d 8b4dfc 83c101 }
		$sequence_5 = { 52 6a00 ff15???????? 68???????? 68???????? }
		$sequence_6 = { e8???????? 83c404 0fbed8 c1e304 }
		$sequence_7 = { 68e8030000 ff15???????? e9???????? 833d????????00 741e 8b0d???????? }
		$sequence_8 = { 8b5510 8a45f9 8802 8b4d10 83c101 }
		$sequence_9 = { 8b0d???????? 51 ff15???????? 6aff 8b15???????? }

	condition:
		7 of them and filesize <98304
}