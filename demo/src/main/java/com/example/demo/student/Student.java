package com.example.demo.student;

public class Student {
	private final Integer studentId;
	private final String studentName;
	
	public Student(Integer sid, String sname) {
		studentId = sid;
		studentName = sname;
	}
	
	public Integer getStudentId() {
		return studentId;
	}

	public String getStudentName() {
		return studentName;
	}

	@Override
	public String toString() {
		return "Student [studentId=" + studentId + ", studentName=" + studentName + "]";
	}

	
}
