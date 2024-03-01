rule MALPEDIA_Win_Roseam_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "88276476-b18b-5edc-880f-eae459b2a660"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roseam"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.roseam_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "3438063035004ab07a2e8d6bda2a389a18e5085289cc780bdf790db5294b5e20"
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
		$sequence_0 = { 895514 eb38 895514 68???????? 68???????? 50 }
		$sequence_1 = { 8b8c2490000000 89442408 8d44240c 6a0a }
		$sequence_2 = { 8b12 66c745ec0200 8955f0 c745fc20000000 68???????? 50 9c }
		$sequence_3 = { f2ae f7d1 49 894dec 8d0489 99 }
		$sequence_4 = { 81fbff000000 895de8 0f84e2010000 8b4df8 83f903 }
		$sequence_5 = { 57 b914000000 be???????? 8d7d90 f3a5 33d2 a4 }
		$sequence_6 = { 58 68???????? ffd6 b91f000000 33c0 }
		$sequence_7 = { 5d 58 8d8d58ffffff 8d95f4fcffff 51 }
		$sequence_8 = { 83c40c f3ab 66ab aa e8???????? 8985f4fcffff }
		$sequence_9 = { 894df0 eb0d 33c9 894dec 894df0 }

	condition:
		7 of them and filesize <221184
}
