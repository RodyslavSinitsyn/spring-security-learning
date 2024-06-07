package org.rsinitsyn;

import lombok.Getter;
import lombok.Setter;

import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
public class Todo {
    private UUID id;
    private String task;
    private boolean completed;
    private String owner;

    public Todo(UUID id, String task, boolean completed, String owner) {
        this.id = id;
        this.task = task;
        this.completed = completed;
        this.owner = owner;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Todo) obj;
        return Objects.equals(this.id, that.id) &&
                Objects.equals(this.task, that.task) &&
                this.completed == that.completed &&
                Objects.equals(this.owner, that.owner);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, task, completed, owner);
    }

    @Override
    public String toString() {
        return "Todo[" +
                "id=" + id + ", " +
                "task=" + task + ", " +
                "completed=" + completed + ", " +
                "owner=" + owner + ']';
    }

}
