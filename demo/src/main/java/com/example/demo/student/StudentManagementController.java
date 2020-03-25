package com.example.demo.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
	private final static List<Student> STUDENTS = Arrays.asList(
			new Student(1,"John Wick"),
			new Student(2,"Mark Ruffalo"),
			new Student(3,"Anna Smith")
			
			);
	
	// hasRole('ROLE_') hasAnyRole('ROLE_')  hasAuthority('permission') hasAnyAuthority('permission')
	
	@GetMapping
	@PreAuthorize("hasAnyRole('ROLE_ADMIN,ROLE_ADMINTRAINEE')")
	public List<Student> getAllStudents() {
		return STUDENTS;
	}
	
	@PostMapping
	@PreAuthorize("hasAuthority('student:write')")
	public void registerNewStudent(@RequestBody Student student) {
		System.out.println(student);
	}
	
	@DeleteMapping(path="{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void deleteStudent(@PathVariable("studentId") Integer studentId) {
		System.out.println(studentId);
	}
	
	@PutMapping(path="{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody Student student) {
		System.out.println(studentId);
		System.out.println(String.format("%s %s", studentId, student));
	}
	
	@GetMapping(path="{studentId}")
	public Student getStudent(@PathVariable("studentId") Integer studentId) {
		return STUDENTS.stream()
				.filter(student -> studentId.equals(student.getStudentId()))
				.findFirst()
				.orElseThrow(() -> new IllegalStateException("Student " + studentId + " does not exist"));
	}
}
