package org.rsinitsyn;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Slf4j
public class TodoService {

    public static final String JOHN_ID = "2e96e13b-1cfd-47fb-bd0d-644ca58b5607";
    public static final String ROMAN_ID = "b760e3bf-a4f2-46fb-8129-f0a5a6ef9bf6";
    public static final String RADIK_ID = "572ab281-c58b-42a2-aac0-64e64cb5d07f";

    List<Todo> todos = new ArrayList<>(List.of(
            new Todo(UUID.fromString(RADIK_ID), "Task #1", false, "radik"),
            new Todo(UUID.fromString(JOHN_ID), "Task #2", false, "john"),
            new Todo(UUID.fromString(ROMAN_ID), "Task #3", false, "roman")
    ));

    public void logTodo(UUID id) {
        getTodoOptional(id).ifPresent(todo -> log.info(todo.toString()));
    }

    @PreAuthorize("hasRole('VERIFIED_USER')")
    public Todo create(String task) {
        var owner = SecurityContextHolder.getContext().getAuthentication().getName();
        Todo newTodo = new Todo(UUID.randomUUID(), task, false, owner);
        todos.add(newTodo);
        return newTodo;
    }

    @PostAuthorize("returnObject.owner == authentication.name")
    public Todo getTodo(UUID id) {
        return todos.stream()
                .filter(todo -> todo.getId().equals(id))
                .findFirst().orElse(null);
    }

    @PostAuthorize("returnObject.present and returnObject.get().owner eq principal.username")
    public Optional<Todo> getTodoOptional(UUID id) {
        return todos.stream()
                .filter(todo -> todo.getId().equals(id))
                .findFirst();
    }


    @PostFilter("filterObject.owner eq principal.username")
    public List<Todo> getTodos() {
        return new ArrayList<>(todos);
    }

    /**
     * Spring Security DELETES items from target returned collection.
     * Check test 'givenGetTodosUnmodified_whenRoman_thenUnsupportedOperationException'
     */
    @PostFilter("filterObject.owner eq principal.username")
    public List<Todo> getTodosUnmodified() {
        return Collections.unmodifiableList(todos);
    }

    public List<Todo> getTodosInternally() {
        return todos;
    }

    @PreFilter("@todoService.isTodoOwner(filterObject, principal.username)")
    public void completeTodos(Collection<UUID> ids) {
        this.todos.stream()
                .filter(todo -> ids.contains(todo.getId()))
                .forEach(todo -> todo.setCompleted(true));
    }

    public boolean isTodoOwner(UUID id, String owner) {
        return this.getTodoOptional(id).map(todo -> todo.getOwner().equals(owner)).orElse(false);
    }
}
