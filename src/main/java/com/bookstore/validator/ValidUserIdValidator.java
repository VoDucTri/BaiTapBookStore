package com.bookstore.validator;

import com.bookstore.entity.User;
import com.bookstore.repository.IUserRepository;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;


public class ValidUserIdValidator implements ConstraintValidator<ValidUserId, User> {
        @Override
        public boolean isValid(User user, ConstraintValidatorContext constraintValidatorContext) {
                if (user == null) {
                        return true; // Bỏ qua validation trường hợp User null
                }
                return user.getId() != null;
        }
}