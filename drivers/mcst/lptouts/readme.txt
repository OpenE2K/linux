Модуль lptouts
Предназначен для непосредственного индивидуального воздействия на сигналы данных параллельного порта повозки.
Разработан для модуля БЦВМ в рамках темы БЦВМ-ИНЭУМ.
Для корректной работы модуля необходимо наличие модулей: parport и parport_povozka.
Модуль не должен быть подключен одновременно с модулями: lp.
Значения вывода после запуска модуля: 0xFF.

Описание работы

Модуль БЦВМ-ИНЭУМ имеет на борту 8 сигналов дискретного вывода, подключенных к линиям данных LPT-порта.
Каналы GPIO не могли быть задействованы для этих целей, т.к. были заняты для обеспечения функций дискретного ввода.
Для пользователя модуль организует интерфейс доступа через sysfs. В /sys/class появляется класс lptouts в котором организуется 8 узлов lptouts1..8 для непосредственного доступа к каждой линии вывода и отдельно узел lptouts для группового управления.
Таким образом, для установки линии данных 2 в значение 1 необходимо выполнить команду:
echo 1 > /sys/class/lptouts/lptouts2/value
или
echo 2 > /sys/class/lptouts/lptouts/value

Все узлы поддерживают функцию чтения, что позволяет прочитать ранее установленное значение. При этом чтение производится непосредственно из регистров LPT порта.
