package com.example.demo.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
	private final static List<Student> STUDENTS = Arrays.asList(
			new Student(1,"Anna Smith"),
			new Student(2,"Linda Hogg"),
			new Student(3,"Tom Hanks")
			
			);
	
	@GetMapping(path="{studentId}")
	public Student getStudent(@PathVariable("studentId") Integer studentId) {
		return STUDENTS.stream()
				.filter(student -> studentId.equals(student.getStudentId()))
				.findFirst()
				.orElseThrow(() -> new IllegalStateException("Student " + studentId + " does not exist"));
	}
}
