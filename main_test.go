package main

import "testing"

func TestGradeRank(t *testing.T) {
	if gradeRank("A+") <= gradeRank("A") || gradeRank("B") <= gradeRank("C") || gradeRank("Z") != -1 {
		t.Error("ordre des notes incorrect")
	}
}
