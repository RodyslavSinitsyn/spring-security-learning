package org.rsinitsyn;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
class TodoServiceTest {

    @Autowired
    private TodoService todoService;

    @Test
    @WithMockUser(roles = "OBSERVER_USER")
    void givenLogTodo_whenHasRole_thenExecute() {
        todoService.logTodo(UUID.fromString(TodoService.RADIK_ID));
    }

    @Test
    @WithMockUser(roles = "VERIFIED_USER")
    void givenLogTodo_whenDontHaveRole_thenForbidden() {
        assertThrows(AccessDeniedException.class, () -> todoService.logTodo(UUID.fromString(TodoService.RADIK_ID)));
    }

    @Test
    @WithMockUser(roles = "VERIFIED_USER")
    void givenCreateTodo_whenHasRole_thenReturnCreatedTodo() {
        String task = "New task";

        var createdTodo = todoService.create(task);

        assertThat(createdTodo).isNotNull();
        assertThat(createdTodo.getOwner()).isNotNull();
        assertThat(createdTodo.getTask()).isEqualTo(task);
    }

    @Test
    @WithMockUser
    void givenCreateTodo_whenDontHaveRole_thenForbidden() {
        assertThrows(AccessDeniedException.class, () -> todoService.create("New task"));
    }

    @Test
    @WithMockUser("radik")
    void givenGetTodo_whenIsOwner_thenReturn() {
        var id = UUID.fromString(TodoService.RADIK_ID);

        var todo = todoService.getTodo(id);

        assertThat(todo).isNotNull();
        assertThat(todo).isEqualTo(new Todo(id, "Task #1", false, "radik"));
    }

    @Test
    @WithMockUser("john")
    void givenGetTodo_whenIsNotOwner_thenForbidden() {
        assertThrows(AccessDeniedException.class, () -> todoService.getTodo(UUID.fromString(TodoService.RADIK_ID)));
    }

    @Test
    @WithMockUser("radik")
    void givenGetTodoOptional_whenIsOwner_thenReturn() {
        var id = UUID.fromString(TodoService.RADIK_ID);

        var todo = todoService.getTodoOptional(id);

        assertThat(todo.isPresent()).isTrue();
        assertThat(todo.get()).isEqualTo(new Todo(id, "Task #1", false, "radik"));
    }

    @Test
    @WithMockUser("john")
    void givenGetTodoOptional_whenIsNotOwner_thenForbidden() {
        assertThrows(AccessDeniedException.class, () -> todoService.getTodoOptional(UUID.fromString(TodoService.RADIK_ID)));
    }

    @Test
    @WithMockUser("roman")
    void givenGetTodos_whenAuthorized_thenReturnOnlyAuthorizedTodos() {
        var todos = todoService.getTodos();

        assertThat(todos).isNotNull().hasSize(1).allSatisfy(todo -> assertThat("roman".equals(todo.getOwner())).isTrue());
    }

    @Test
    @WithMockUser("roman")
    void givenGetTodosUnmodified_whenExecute_thenUnsupportedOperationException() {
        assertThrows(UnsupportedOperationException.class, () -> todoService.getTodosUnmodified());
    }

    @Test
    @WithMockUser("john")
    void givenCompleteTodos_whenCompleteManyTodos_thenActuallyCompleteOnlyOwnersOne() {
        todoService.completeTodos(new ArrayList<>(List.of(
                UUID.fromString(TodoService.JOHN_ID),
                UUID.fromString(TodoService.ROMAN_ID)
        )));

        todoService.getTodosInternally().stream()
                .filter(todo -> todo.getId().toString().equals(TodoService.JOHN_ID))
                .findFirst().ifPresent(todo -> assertThat(todo.isCompleted()).isTrue());

        todoService.getTodosInternally().stream()
                .filter(todo -> todo.getId().toString().equals(TodoService.ROMAN_ID))
                .findFirst().ifPresent(todo -> assertThat(todo.isCompleted()).isFalse());
    }
}