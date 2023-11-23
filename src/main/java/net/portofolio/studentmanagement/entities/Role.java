package net.portofolio.studentmanagement.entities;

import lombok.*;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;


@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@Table(name = "trx_roles")
public class Role {

    @Id
    @GenericGenerator(strategy = "uuid2", name="system-uuid")
    @GeneratedValue(generator = "system-uuid")
    @Column(name = "role_id")
    private String id;

    @Column(unique = true)
    private String name;
}
